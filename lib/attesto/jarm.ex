defmodule Attesto.JARM do
  @moduledoc """
  JWT Secured Authorization Response Mode (JARM).

  Builds the signed JWT an authorization server returns to a client as the
  single `response` parameter when a JWT response mode (`jwt`, `query.jwt`,
  `fragment.jwt`, `form_post.jwt`) is requested, giving the authorization
  response non-repudiation and integrity (FAPI 2.0 Message Signing §5.4).

  This is conn-free core: it turns the issuer/keystore on the `Attesto.Config`,
  the client identifier, and a map of authorization-response parameters (the
  `code`/`state`/`iss` of a success, or the `error`/`error_description`/`state`
  of a failure) into a compact JWS. The transport layer (the authorization
  endpoint) decides the response mode and how the resulting JWT is delivered
  (redirect query/fragment or auto-submitting form); nothing here touches HTTP.

  ## JWT claims (JARM §2.1)

    * `iss` - REQUIRED, the authorization server's issuer identifier.
    * `aud` - REQUIRED, the client the response is addressed to (`client_id`).
    * `exp` - REQUIRED, expiration; the response is short-lived.
    * `iat` - the issuance time.
    * every supplied authorization-response parameter, verbatim, as a top-level
      claim (`code`, `state`, `iss`-echo for success; `error`,
      `error_description`, `error_uri`, `state` for failure).

  Signing mirrors `Attesto.IDToken`: the keystore's current signing key and its
  algorithm (`Attesto.SigningAlg.for_key/3`), with the `kid` in the JOSE header,
  signed with that pinned algorithm (never `none`).
  """

  alias Attesto.{Claims, Config, JWS, NumericDate}

  # JARM responses are consumed immediately by the client on the redirect, so
  # the JWT is short-lived. `:lifetime` may only shorten this default.
  @default_lifetime_seconds 600

  @type response_params :: %{optional(String.t()) => String.t() | nil}

  @type opts :: [now: integer() | DateTime.t(), lifetime: pos_integer()]

  @doc """
  Build and sign the JARM response JWT for `client_id`, carrying `params`.

  `params` is the authorization-response parameter map; `nil` values are
  dropped (an absent `state`/`error_uri` is not advertised). Returns
  `{:ok, compact_jws}`.

  Options:

    * `:now` - the issuance time (integer Unix seconds or `DateTime`), for
      deterministic tests; defaults to the current time.
    * `:lifetime` - the JWT lifetime in seconds; may only shorten the
      `#{@default_lifetime_seconds}`-second default.
  """
  @spec response_jwt(Config.t(), String.t(), response_params(), opts()) ::
          {:ok, String.t()}
  def response_jwt(%Config{} = config, client_id, params, opts \\ [])
      when is_binary(client_id) and client_id != "" and is_map(params) do
    now = NumericDate.now(opts)

    claims =
      params
      |> drop_nil()
      |> stringify_keys()
      |> Map.merge(%{
        "iss" => config.issuer,
        "aud" => client_id,
        "iat" => now,
        "exp" => now + NumericDate.bounded_lifetime(opts, :lifetime, @default_lifetime_seconds)
      })

    {:ok, JWS.sign_current(config.keystore, claims)}
  end

  defp drop_nil(params) do
    params
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  # The reserved claims (`iss`, `aud`, `iat`, `exp`) are set by the merge below,
  # and a string key there overwrites a caller's string key of the same name -
  # the server value wins. A key of any OTHER type that still serializes to the
  # same JSON member name (an atom `:iss`, a charlist `~c"iss"`) is a distinct
  # map key, so it would survive the merge and produce a DUPLICATE JSON member
  # whose value a lenient parser might prefer. Guarantee the invariant "every
  # key is a binary" here: convert atoms, pass binaries, and reject anything
  # else - so the merge is authoritative and the JWT can never carry a duplicate
  # claim. (`params`'s contract is string keys; this hardens the public core
  # against a caller that violates it rather than trusting the contract.)
  defp stringify_keys(params) do
    case Claims.normalize_keys(params, atoms: :convert) do
      {:ok, normalized} ->
        normalized

      {:error, {:invalid_key, key}} ->
        raise ArgumentError,
              "JARM response params must have string keys (atoms are converted); " <>
                "a #{inspect(key)} key could forge a duplicate reserved claim"

      {:error, _reason} ->
        raise ArgumentError, "invalid JARM response params"
    end
  end
end
