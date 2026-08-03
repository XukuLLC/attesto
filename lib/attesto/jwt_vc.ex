defmodule Attesto.JwtVc do
  @moduledoc """
  W3C Verifiable Credentials Data Model 1.1 credentials encoded as JWTs,
  corresponding to the OID4VCI `jwt_vc_json` Credential Format.

  A JWT VC is a compact JWS whose payload contains a `vc` object alongside
  registered JWT claims. This module emits the following representation:

      {
        "iss" => issuer,
        "sub" => subject,
        "nbf" => not_before,
        "exp" => expires_at,
        "iat" => issued_at,
        "jti" => credential_id,
        "cnf" => confirmation,
        "vc" => %{
          "@context" => ["https://www.w3.org/2018/credentials/v1"],
          "type" => ["VerifiableCredential", credential_type],
          "credentialSubject" => credential_claims,
          "issuer" => issuer
        }
      }

  W3C VC Data Model 1.1 section 6.3.1 defines the JWT mapping: `vc` is
  required; `iss`, `sub`, `nbf`, `exp`, and `jti` represent the corresponding
  VC issuer, subject id, issuance date, expiration date, and credential id.
  `iat` is also emitted as the actual signing time. The JOSE `typ` is `JWT`, as
  required by that mapping when the header is present. OID4VCI draft 17
  Appendix A.1.1 calls this non-JSON-LD JWS representation `jwt_vc_json` and
  carries the compact JWT directly in the Credential Response.

  Holder binding is represented by an optional RFC 7800 `cnf` claim. This
  module binds the confirmation material into the issuer signature and returns
  it after verification; proving possession of the referenced private key is a
  separate presentation-protocol step.

  Issuance accepts either an `Attesto.Keystore` module or a private PEM.
  Verification is conn-free and uses only caller-supplied trusted issuer JWKS.
  It requires all registered claims this module emits, rejects malformed or
  absent temporal claims, and verifies the signature before returning any
  credential data.
  """

  alias Attesto.{JWS, Key, MapParams, NumericDate, SigningAlg}

  @context "https://www.w3.org/2018/credentials/v1"
  @header_typ "JWT"
  @default_lifetime_seconds 3600
  @clock_skew_seconds 60
  @confirmation_methods ~w(jwk jwe jku kid)
  @private_jwk_members ~w(d p q dp dq qi oth k)

  @type issue_source :: keyword() | module() | String.t()

  @type issue_opts :: [
          {:iss, String.t()}
          | {:sub, String.t()}
          | {:claims, map()}
          | {:credential_subject, map()}
          | {:context, [String.t() | map()]}
          | {:type, [String.t()]}
          | {:iat, non_neg_integer()}
          | {:nbf, non_neg_integer()}
          | {:exp, non_neg_integer()}
          | {:lifetime, pos_integer()}
          | {:jti, String.t()}
          | {:cnf, map()}
          | {:now, DateTime.t() | non_neg_integer()}
          | {:keystore, module()}
          | {:pem, String.t()}
          | {:alg, SigningAlg.alg()}
          | {:kid, String.t()}
        ]

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:issuer, String.t()}
          | {:accepted_algs, [SigningAlg.alg()]}
        ]

  @type verified :: %{
          claims: map(),
          vc: map(),
          cnf: map() | nil,
          iss: String.t(),
          sub: String.t(),
          jwt_claims: map()
        }

  @type verify_error ::
          :invalid_credential
          | :unsupported_critical_header
          | :invalid_typ
          | :unsupported_alg
          | :invalid_signature
          | :invalid_claims
          | :invalid_vc
          | :invalid_issuer
          | :invalid_cnf
          | :expired
          | :not_yet_valid

  @doc """
  Issue a signed W3C JWT VC.

  The first argument may be a keyword list containing all options, a keystore
  module, or a private signing-key PEM. When it is a keyword list, pass exactly
  one of `:keystore` and `:pem`. A keystore uses `Attesto.JWS.sign_current/3`;
  a PEM derives its algorithm and default `kid` from the same parsed key.

  Required options are `:iss` and `:sub`. Subject claims can be supplied as
  `:claims` (matching `Attesto.SdJwtVc`) or `:credential_subject`; they default
  to an empty map. `:context` defaults to the VC 1.1 base context and `:type`
  defaults to `["VerifiableCredential"]`.

  `iat` and `nbf` default to `:now`; `exp` defaults to one hour after `iat`
  (or the positive `:lifetime`); and `jti` defaults to a random UUID URN. Pass
  `:cnf`, for example `%{"jwk" => holder_public_jwk}`, to bind the credential
  to holder key material under RFC 7800.

  Returns the compact JWT string. Invalid issuer input is a programming or
  configuration error and raises `ArgumentError`, matching the issuance style
  of `Attesto.SdJwtVc`.
  """
  @spec issue(issue_source(), issue_opts()) :: String.t()
  def issue(source, opts \\ [])

  def issue(required, opts) when is_list(required) and is_list(opts) do
    required = MapParams.ensure_keyword!(required)
    opts = MapParams.ensure_keyword!(opts)

    required
    |> Keyword.merge(opts)
    |> issue_from_opts()
  end

  def issue(keystore, opts) when is_atom(keystore) and is_list(opts) do
    opts
    |> MapParams.ensure_keyword!()
    |> Keyword.put(:keystore, keystore)
    |> issue_from_opts()
  end

  def issue(pem, opts) when is_binary(pem) and is_list(opts) do
    opts
    |> MapParams.ensure_keyword!()
    |> Keyword.put(:pem, pem)
    |> issue_from_opts()
  end

  def issue(source, opts) do
    raise ArgumentError,
          "issue/2 expects a keyword list, keystore module, or private PEM and keyword options; " <>
            "got #{inspect(source)} and #{inspect(opts)}"
  end

  @doc """
  Verify a W3C JWT VC against trusted issuer keys.

  `trusted_jwks` may be an RFC 7517 JWK Set, a single public JWK map, or a
  list of public JWK maps. Verification requires `typ: JWT`, rejects critical
  JOSE extensions, binds the algorithm to each trusted key, and then validates
  the W3C `vc` object and all registered claims emitted by `issue/2`.

  Temporal validation is fail-closed: `iat`, `nbf`, and `exp` must all be
  non-negative integer NumericDates; `exp` must be strictly in the future;
  and `iat`/`nbf` may be no more than 60 seconds ahead of the verifier clock.
  Pass `:issuer` to additionally pin `iss` to an expected identifier. The
  nested VC issuer always has to agree with `iss`.

  On success, `:claims` is the VC `credentialSubject`, `:vc` is the complete
  nested VC object, `:cnf` is the optional holder confirmation object, and
  `:jwt_claims` retains the complete signed JWT payload.
  """
  @spec verify(String.t(), map() | [map()], verify_opts()) ::
          {:ok, verified()} | {:error, verify_error()}
  def verify(jwt, trusted_jwks, opts \\ [])

  def verify(jwt, trusted_jwks, opts) when is_binary(jwt) and is_list(opts) do
    opts = MapParams.ensure_keyword!(opts)

    with {:ok, header} <- parse_header(jwt),
         :ok <- check_crit(header),
         :ok <- check_typ(header),
         :ok <- check_alg(header, opts),
         {:ok, jwt_claims} <- verify_signature(jwt, header, trusted_jwks, opts),
         {:ok, registered} <- registered_claims(jwt_claims),
         :ok <- check_expected_issuer(registered.iss, opts),
         {:ok, vc, claims} <- validate_vc(jwt_claims, registered),
         {:ok, cnf} <- validate_verified_cnf(Map.get(jwt_claims, "cnf")),
         :ok <- check_temporal(registered, NumericDate.now(opts)) do
      {:ok,
       %{
         claims: claims,
         vc: vc,
         cnf: cnf,
         iss: registered.iss,
         sub: registered.sub,
         jwt_claims: jwt_claims
       }}
    end
  end

  def verify(_jwt, _trusted_jwks, _opts), do: {:error, :invalid_credential}

  defp issue_from_opts(opts) do
    iss = opts |> Keyword.fetch!(:iss) |> MapParams.required_string!(:iss)
    sub = opts |> Keyword.fetch!(:sub) |> MapParams.required_string!(:sub)
    credential_subject = credential_subject!(opts)
    context = context!(Keyword.get(opts, :context, [@context]))
    types = types!(Keyword.get(opts, :type, ["VerifiableCredential"]))
    iat = numeric_date!(Keyword.get(opts, :iat, NumericDate.now(opts)), :iat)
    nbf = numeric_date!(Keyword.get(opts, :nbf, iat), :nbf)

    exp =
      opts
      |> Keyword.get(:exp, iat + NumericDate.bounded_lifetime(opts, :lifetime, @default_lifetime_seconds))
      |> numeric_date!(:exp)

    jti =
      opts
      |> Keyword.get_lazy(:jti, &random_jti/0)
      |> MapParams.required_string!(:jti)

    cnf = validate_issued_cnf!(Keyword.get(opts, :cnf))

    vc = %{
      "@context" => context,
      "type" => types,
      "credentialSubject" => credential_subject,
      "issuer" => iss
    }

    claims =
      %{
        "vc" => vc,
        "iss" => iss,
        "sub" => sub,
        "nbf" => nbf,
        "exp" => exp,
        "iat" => iat,
        "jti" => jti
      }
      |> MapParams.put_optional("cnf", cnf)

    sign(claims, opts)
  end

  defp credential_subject!(opts) do
    subject =
      case {Keyword.fetch(opts, :claims), Keyword.fetch(opts, :credential_subject)} do
        {:error, :error} ->
          %{}

        {{:ok, claims}, :error} ->
          claims

        {:error, {:ok, claims}} ->
          claims

        {{:ok, claims}, {:ok, claims}} ->
          claims

        {{:ok, _claims}, {:ok, _credential_subject}} ->
          raise ArgumentError, ":claims and :credential_subject must not disagree"
      end

    if is_map(subject) do
      MapParams.string_keyed_map(subject)
    else
      raise ArgumentError, ":claims/:credential_subject must be a map; got #{inspect(subject)}"
    end
  end

  defp context!([@context | rest] = context) do
    if Enum.all?(rest, &(is_binary(&1) or is_map(&1))) do
      context
    else
      raise ArgumentError, ":context entries after the VC 1.1 base context must be strings or maps"
    end
  end

  defp context!(context) do
    raise ArgumentError,
          ":context must be a non-empty list beginning with #{inspect(@context)}; got #{inspect(context)}"
  end

  defp types!(types) when is_list(types) and types != [] do
    if Enum.all?(types, &(is_binary(&1) and &1 != "")) and "VerifiableCredential" in types do
      types
    else
      raise ArgumentError, ":type must be a non-empty string list containing \"VerifiableCredential\""
    end
  end

  defp types!(_types) do
    raise ArgumentError, ":type must be a non-empty string list containing \"VerifiableCredential\""
  end

  defp numeric_date!(value, _name) when is_integer(value) and value >= 0, do: value

  defp numeric_date!(value, name) do
    raise ArgumentError, ":#{name} must be a non-negative integer NumericDate; got #{inspect(value)}"
  end

  defp validate_issued_cnf!(nil), do: nil

  defp validate_issued_cnf!(cnf) when is_map(cnf) do
    cnf =
      cnf
      |> MapParams.string_keyed_map()
      |> normalize_issued_cnf_jwk()

    case validate_cnf(cnf) do
      :ok -> cnf
      {:error, :invalid_cnf} -> raise ArgumentError, ":cnf must identify one RFC 7800 confirmation key"
    end
  end

  defp validate_issued_cnf!(_cnf), do: raise(ArgumentError, ":cnf must identify one RFC 7800 confirmation key")

  defp normalize_issued_cnf_jwk(%{"jwk" => jwk} = cnf) when is_map(jwk) do
    Map.put(cnf, "jwk", MapParams.string_keyed_map(jwk))
  end

  defp normalize_issued_cnf_jwk(cnf), do: cnf

  defp sign(claims, opts) do
    case {Keyword.get(opts, :keystore), Keyword.get(opts, :pem)} do
      {keystore, nil} when is_atom(keystore) and not is_nil(keystore) ->
        JWS.sign_current(keystore, claims, typ: @header_typ)

      {nil, pem} when is_binary(pem) and pem != "" ->
        sign_with_pem(pem, claims, opts)

      {nil, nil} ->
        raise ArgumentError, "exactly one of :keystore or :pem is required"

      {_keystore, _pem} ->
        raise ArgumentError, "exactly one of :keystore or :pem is required"
    end
  end

  defp sign_with_pem(pem, claims, opts) do
    jwk = Key.signing_jwk(pem)
    alg = opts |> Keyword.get(:alg, SigningAlg.infer(jwk)) |> SigningAlg.validate_for_key!(jwk)
    kid = opts |> Keyword.get(:kid, Key.kid(pem)) |> MapParams.required_string!(:kid)

    JWS.sign_compact(pem, %{"alg" => alg, "kid" => kid, "typ" => @header_typ}, claims)
  end

  defp parse_header(jwt) do
    case JWS.peek_json(jwt, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :invalid_credential}
    end
  end

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp check_typ(%{"typ" => @header_typ}), do: :ok
  defp check_typ(_header), do: {:error, :invalid_typ}

  defp check_alg(header, opts) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    case Map.get(header, "alg") do
      alg when is_binary(alg) and alg != "none" ->
        if is_list(accepted) and alg in SigningAlg.allowed() and (accepted == [] or alg in accepted),
          do: :ok,
          else: {:error, :unsupported_alg}

      _other ->
        {:error, :unsupported_alg}
    end
  end

  defp verify_signature(jwt, header, trusted_jwks, opts) do
    candidates =
      JWS.verification_candidates(trusted_jwks,
        kid: Map.get(header, "kid"),
        accepted_algs: Keyword.get(opts, :accepted_algs, SigningAlg.allowed()),
        malformed_key: :reject_set
      )

    JWS.verify_strict(jwt, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_credential,
      claims_map?: true
    )
  end

  defp registered_claims(claims) do
    with {:ok, iss} <- required_string(claims, "iss"),
         {:ok, sub} <- required_string(claims, "sub"),
         {:ok, jti} <- required_string(claims, "jti"),
         {:ok, iat} <- required_numeric_date(claims, "iat"),
         {:ok, nbf} <- required_numeric_date(claims, "nbf"),
         {:ok, exp} <- required_numeric_date(claims, "exp") do
      {:ok, %{iss: iss, sub: sub, jti: jti, iat: iat, nbf: nbf, exp: exp}}
    end
  end

  defp required_string(claims, key) do
    case Map.get(claims, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _other -> {:error, :invalid_claims}
    end
  end

  defp required_numeric_date(claims, key) do
    case NumericDate.fetch(claims, key, required: true, non_negative: true) do
      {:ok, value} -> {:ok, value}
      _other -> {:error, :invalid_claims}
    end
  end

  defp check_expected_issuer(iss, opts) do
    case Keyword.get(opts, :issuer) do
      nil -> :ok
      ^iss -> :ok
      _other -> {:error, :invalid_issuer}
    end
  end

  defp validate_vc(%{"vc" => vc}, registered) when is_map(vc) do
    with :ok <- valid_context(Map.get(vc, "@context")),
         :ok <- valid_types(Map.get(vc, "type")),
         {:ok, credential_subject} <- valid_credential_subject(Map.get(vc, "credentialSubject")),
         :ok <- matching_issuer(Map.get(vc, "issuer"), registered.iss),
         :ok <- matching_optional_id(Map.get(vc, "id"), registered.jti),
         :ok <- matching_optional_id(Map.get(credential_subject, "id"), registered.sub) do
      {:ok, vc, credential_subject}
    end
  end

  defp validate_vc(_claims, _registered), do: {:error, :invalid_vc}

  defp valid_context([@context | rest]) do
    if Enum.all?(rest, &(is_binary(&1) or is_map(&1))), do: :ok, else: {:error, :invalid_vc}
  end

  defp valid_context(_context), do: {:error, :invalid_vc}

  defp valid_types(types) when is_list(types) and types != [] do
    if Enum.all?(types, &(is_binary(&1) and &1 != "")) and "VerifiableCredential" in types,
      do: :ok,
      else: {:error, :invalid_vc}
  end

  defp valid_types(_types), do: {:error, :invalid_vc}

  defp valid_credential_subject(subject) when is_map(subject), do: {:ok, subject}
  defp valid_credential_subject(_subject), do: {:error, :invalid_vc}

  defp matching_issuer(issuer, expected) when issuer == expected, do: :ok
  defp matching_issuer(%{"id" => expected}, expected), do: :ok
  defp matching_issuer(_issuer, _expected), do: {:error, :invalid_issuer}

  defp matching_optional_id(nil, _expected), do: :ok
  defp matching_optional_id(expected, expected), do: :ok
  defp matching_optional_id(_actual, _expected), do: {:error, :invalid_vc}

  defp validate_verified_cnf(nil), do: {:ok, nil}

  defp validate_verified_cnf(cnf) do
    case validate_cnf(cnf) do
      :ok -> {:ok, cnf}
      {:error, :invalid_cnf} = error -> error
    end
  end

  defp validate_cnf(cnf) when is_map(cnf) and map_size(cnf) > 0 do
    methods = Enum.filter(@confirmation_methods, &Map.has_key?(cnf, &1))

    if length(methods) <= 1 and valid_confirmation_method(cnf, methods) do
      :ok
    else
      {:error, :invalid_cnf}
    end
  end

  defp validate_cnf(_cnf), do: {:error, :invalid_cnf}

  defp valid_confirmation_method(cnf, ["jwk"]) do
    case Map.get(cnf, "jwk") do
      jwk when is_map(jwk) and map_size(jwk) > 0 ->
        not Enum.any?(@private_jwk_members, &Map.has_key?(jwk, &1)) and parseable_jwk?(jwk)

      _other ->
        false
    end
  end

  defp valid_confirmation_method(cnf, [method]) when method in ~w(jwe jku kid) do
    value = Map.get(cnf, method)
    is_binary(value) and value != ""
  end

  defp valid_confirmation_method(_cnf, []), do: true

  defp parseable_jwk?(jwk) do
    match?(%JOSE.JWK{}, JOSE.JWK.from_map(jwk))
  rescue
    _error -> false
  catch
    _kind, _reason -> false
  end

  defp check_temporal(%{iat: iat, nbf: nbf, exp: exp}, now) do
    cond do
      not NumericDate.not_expired?(exp, now, leeway: 0) -> {:error, :expired}
      not NumericDate.not_before_reached?(nbf, now, skew: @clock_skew_seconds) -> {:error, :not_yet_valid}
      not NumericDate.not_before_reached?(iat, now, skew: @clock_skew_seconds) -> {:error, :not_yet_valid}
      exp <= nbf or exp <= iat -> {:error, :invalid_claims}
      true -> :ok
    end
  end

  defp random_jti do
    <<a::binary-size(6), byte_6, byte_7, byte_8, rest::binary-size(7)>> = :crypto.strong_rand_bytes(16)
    bytes = a <> <<rem(byte_6, 16) + 64, byte_7, rem(byte_8, 64) + 128>> <> rest
    hex = Base.encode16(bytes, case: :lower)
    <<p1::binary-size(8), p2::binary-size(4), p3::binary-size(4), p4::binary-size(4), p5::binary-size(12)>> = hex
    "urn:uuid:#{p1}-#{p2}-#{p3}-#{p4}-#{p5}"
  end
end
