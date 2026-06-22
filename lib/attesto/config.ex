defmodule Attesto.Config do
  @moduledoc """
  Immutable configuration a token operation runs against.

  A `Config` binds together everything `Attesto.Token` needs that is
  policy rather than protocol: who the issuer and audience are, where keys
  come from, what principal kinds exist, and the default token lifetime.
  Build one once (typically memoised by the host application) and pass it
  to `Attesto.Token.mint/3` and `Attesto.Token.verify/3`.

  ## Fields

    * `:issuer` - the `iss` claim value minted into every token and
      required to match on verify. A non-empty string (an `https://` URL
      in any real deployment).
    * `:audience` - the `aud` claim value. A non-empty string.
    * `:keystore` - a module implementing `Attesto.Keystore`.
    * `:principal_kinds` - the non-empty list of `Attesto.PrincipalKind`
      structs this issuer serves. Their `claim_value`s must be distinct,
      and their `sub_prefix`es must be distinct, so the kind a token
      claims and the subject it carries map unambiguously.
    * `:principal_kind_claim` - the JWT claim name that carries the
      principal kind's `claim_value`. Defaults to `"principal_kind"`.
      A host may set its own (e.g. a namespaced private claim) without
      changing any other behaviour.
    * `:default_lifetime_seconds` - access-token lifetime when a caller
      does not request a shorter one. Defaults to `900` (15 minutes).
    * `:token_endpoint_path` - the request path the token endpoint is
      mounted at, used to derive `token_endpoint_url/1` (the URL a DPoP
      proof's `htu` must sign, and the URL OAuth metadata would publish).
      Defaults to `"/oauth/token"`.

  ## Reserved claims

  The claim names Attesto assembles itself - `iss`, `aud`, `exp`, `iat`,
  `jti`, `sub`, `scope`, `typ`, `cnf`, and the configured
  `principal_kind_claim` - are reserved. `Attesto.Token.mint/3` refuses a
  principal whose extra claims would collide with one of them, so a caller
  can never shadow a protocol claim.
  """

  alias Attesto.PrincipalKind

  @enforce_keys [:issuer, :audience, :keystore, :principal_kinds]
  defstruct [
    :issuer,
    :audience,
    :keystore,
    :principal_kinds,
    principal_kind_claim: "principal_kind",
    default_lifetime_seconds: 900,
    token_endpoint_path: "/oauth/token",
    access_token_header_typ: "at+jwt"
  ]

  @type t :: %__MODULE__{
          issuer: String.t(),
          audience: String.t(),
          keystore: module(),
          principal_kinds: [PrincipalKind.t(), ...],
          principal_kind_claim: String.t(),
          default_lifetime_seconds: pos_integer(),
          token_endpoint_path: String.t(),
          access_token_header_typ: String.t() | nil
        }

  # `acr` / `auth_time` are the RFC 9470 / OIDC Core authentication-context
  # claims. They are reserved so they can only be written via the authoritative,
  # host-asserted `Attesto.Token.mint/3` `:acr` / `:auth_time` opts - never
  # smuggled in through a principal's free-form `:claims` (which could otherwise
  # forge a token that satisfies a step-up requirement).
  @reserved_claims ~w(iss aud exp iat jti sub scope typ cnf acr auth_time)

  @doc """
  Build and validate a `Config`.

      Attesto.Config.new(
        issuer: "https://api.example/",
        audience: "https://api.example/",
        keystore: MyApp.Keystore,
        principal_kinds: [
          Attesto.PrincipalKind.new("client", "oc_",
            required_claims: [{"client_id", :non_empty_string}]),
          Attesto.PrincipalKind.new("user", "usr_",
            required_claims: [
              {"act", :non_empty_string},
              {"sid", :non_empty_string},
              {"token_version", :non_neg_integer}
            ])
        ]
      )

  Raises `ArgumentError` on a malformed configuration (blank issuer or
  audience, a keystore that is not a module, an empty or non-list
  principal-kind set, duplicate `claim_value`s or `sub_prefix`es, or a
  `principal_kind_claim` that collides with a reserved claim). This is
  evaluated once at boot, so it fails loudly rather than at the first
  token operation.
  """
  @spec new(keyword()) :: t()
  def new(opts) when is_list(opts) do
    config = struct!(__MODULE__, opts)

    validate_binary!(:issuer, config.issuer)
    validate_issuer_url!(config.issuer)
    validate_binary!(:audience, config.audience)
    validate_keystore!(config.keystore)
    validate_principal_kind_claim!(config.principal_kind_claim)
    validate_principal_kinds!(config.principal_kinds)
    validate_lifetime!(config.default_lifetime_seconds)
    validate_token_endpoint_path!(config.token_endpoint_path)
    validate_access_token_header_typ!(config.access_token_header_typ)

    config
  end

  @doc """
  Return the `Attesto.PrincipalKind` whose `claim_value` equals
  `claim_value`, or `nil` if no configured kind matches.
  """
  @spec principal_kind(t(), term()) :: PrincipalKind.t() | nil
  def principal_kind(%__MODULE__{principal_kinds: kinds}, claim_value) do
    Enum.find(kinds, fn %PrincipalKind{claim_value: v} -> v == claim_value end)
  end

  @doc """
  The canonical external URL of the token endpoint: the configured issuer
  merged with `token_endpoint_path`. This is the URL a client's DPoP proof
  must sign in its `htu` claim (RFC 9449 §4.3) and the URL OAuth
  Authorization Server Metadata (RFC 8414) would publish. Derived from
  `issuer` rather than a live request so it is stable behind any TLS
  terminator or reverse proxy.
  """
  @spec token_endpoint_url(t()) :: String.t()
  def token_endpoint_url(%__MODULE__{issuer: issuer, token_endpoint_path: path}) do
    issuer
    |> URI.parse()
    |> URI.merge(path)
    |> URI.to_string()
  end

  @doc false
  @spec reserved_claims(t()) :: [String.t()]
  def reserved_claims(%__MODULE__{principal_kind_claim: claim}), do: [claim | @reserved_claims]

  # RFC 8414 §2: the issuer identifier MUST be an `https` URL with a host
  # and no query or fragment. The same value is the JWT `iss`, so enforcing
  # the metadata shape here keeps a misconfigured deployment from
  # publishing (and minting tokens under) a non-conformant issuer.
  defp validate_issuer_url!(issuer) do
    uri = URI.parse(issuer)

    cond do
      uri.scheme != "https" ->
        raise ArgumentError,
              "Attesto.Config :issuer must be an https URL (RFC 8414 §2); got #{inspect(issuer)}"

      uri.host in [nil, ""] ->
        raise ArgumentError, "Attesto.Config :issuer must include a host; got #{inspect(issuer)}"

      not is_nil(uri.query) ->
        raise ArgumentError,
              "Attesto.Config :issuer must not carry a query component (RFC 8414 §2); " <>
                "got #{inspect(issuer)}"

      not is_nil(uri.fragment) ->
        raise ArgumentError,
              "Attesto.Config :issuer must not carry a fragment (RFC 8414 §2); " <>
                "got #{inspect(issuer)}"

      true ->
        :ok
    end
  end

  defp validate_binary!(field, value) do
    if !(is_binary(value) and value != "") do
      raise ArgumentError, "Attesto.Config #{field} must be a non-empty string; got #{inspect(value)}"
    end
  end

  defp validate_keystore!(module) when is_atom(module) and not is_nil(module), do: :ok

  defp validate_keystore!(other),
    do: raise(ArgumentError, "Attesto.Config :keystore must be a module; got #{inspect(other)}")

  defp validate_principal_kind_claim!(claim) do
    validate_binary!(:principal_kind_claim, claim)

    if claim in @reserved_claims do
      raise ArgumentError,
            "Attesto.Config :principal_kind_claim #{inspect(claim)} collides with a reserved " <>
              "protocol claim (#{Enum.join(@reserved_claims, ", ")})."
    end
  end

  defp validate_principal_kinds!([_ | _] = kinds) do
    Enum.each(kinds, fn
      %PrincipalKind{} ->
        :ok

      other ->
        raise ArgumentError,
              "Attesto.Config :principal_kinds must all be %Attesto.PrincipalKind{}; got #{inspect(other)}"
    end)

    assert_unique!(kinds, & &1.claim_value, "claim_value")
    assert_unique!(kinds, & &1.sub_prefix, "sub_prefix")
    :ok
  end

  defp validate_principal_kinds!(other) do
    raise ArgumentError,
          "Attesto.Config :principal_kinds must be a non-empty list of " <>
            "%Attesto.PrincipalKind{}; got #{inspect(other)}"
  end

  defp validate_lifetime!(n) when is_integer(n) and n > 0, do: :ok

  defp validate_lifetime!(other),
    do:
      raise(ArgumentError, "Attesto.Config :default_lifetime_seconds must be a positive integer; got #{inspect(other)}")

  # The path is merged onto the issuer to derive `token_endpoint_url/1`.
  # Require a path-only absolute URI reference: exactly one leading `/`, no
  # authority, query, or fragment. `URI.merge/2` treats `//host/path` as a
  # network-path reference and would otherwise switch hosts.
  defp validate_token_endpoint_path!(path) when is_binary(path) do
    uri = URI.parse(path)

    cond do
      not String.starts_with?(path, "/") ->
        raise_invalid_token_endpoint_path!(path)

      String.starts_with?(path, "//") ->
        raise_invalid_token_endpoint_path!(path)

      uri.path != path or uri.query != nil or uri.fragment != nil or uri.host != nil ->
        raise_invalid_token_endpoint_path!(path)

      true ->
        :ok
    end
  end

  defp validate_token_endpoint_path!(other) do
    raise_invalid_token_endpoint_path!(other)
  end

  defp raise_invalid_token_endpoint_path!(other) do
    raise ArgumentError,
          "Attesto.Config :token_endpoint_path must be a path-only absolute URI reference " <>
            "beginning with a single \"/\" and carrying no query or fragment; got #{inspect(other)}"
  end

  # `nil` means "emit no `typ` header"; otherwise it must be a non-empty
  # string (the media type stamped into the access-token JOSE header). An
  # empty string would be silently dropped at sign time, so reject it.
  defp validate_access_token_header_typ!(nil), do: :ok
  defp validate_access_token_header_typ!(typ) when is_binary(typ) and typ != "", do: :ok

  defp validate_access_token_header_typ!(other) do
    raise ArgumentError,
          "Attesto.Config :access_token_header_typ must be a non-empty string or nil; " <>
            "got #{inspect(other)}"
  end

  defp assert_unique!(kinds, fun, label) do
    values = Enum.map(kinds, fun)

    if length(Enum.uniq(values)) != length(values) do
      raise ArgumentError,
            "Attesto.Config principal kinds must have distinct #{label}s; got #{inspect(values)}"
    end
  end
end
