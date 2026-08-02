defmodule Attesto.ClientAssertion do
  @moduledoc """
  `private_key_jwt` client authentication verification (RFC 7523 / OIDC Core).

  The host owns client registration and key storage. This module only verifies
  a compact client assertion against trusted client JWKs supplied by the host
  and checks the standard claims:

    * `iss` and `sub` equal the OAuth `client_id`
    * `aud` contains the expected token endpoint/audience
    * `exp` is in the future
    * `iat`, when present, is not meaningfully in the future
    * `jti` is present for replay tracking by the caller

  The JOSE algorithm is resolved from the trusted JWK's `alg` member when
  present, otherwise from the key shape. It is never accepted just because the
  presented JWT header names it.
  """

  alias Attesto.{Claims, JWS}
  alias Attesto.NumericDate
  alias Attesto.SigningAlg

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @clock_skew_seconds 60

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:max_lifetime, pos_integer()}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:enforce_fapi_alg_policy, boolean()}
        ]

  @type verify_error ::
          :invalid_assertion
          | :invalid_signature
          | :invalid_client_id
          | :invalid_audience
          | :expired
          | :not_yet_valid
          | :missing_jti
          | :unsupported_critical_header

  @doc "The required `client_assertion_type` value for `private_key_jwt`."
  @spec assertion_type() :: String.t()
  def assertion_type, do: @assertion_type

  @doc "Peek `iss` from an assertion without trusting it."
  @spec peek_client_id(String.t()) :: {:ok, String.t()} | {:error, :invalid_assertion}
  def peek_client_id(assertion) when is_binary(assertion) do
    with {:ok, claims} <- peek_payload(assertion),
         iss when is_binary(iss) and iss != "" <- Map.get(claims, "iss") do
      {:ok, iss}
    else
      _ -> {:error, :invalid_assertion}
    end
  end

  def peek_client_id(_), do: {:error, :invalid_assertion}

  @doc """
  Verify a client assertion against the client's trusted JWK Set.

  `trusted_jwks` may be an RFC 7517 JWK Set (`%{"keys" => [...]}`), a single
  public JWK map, or a list of public JWK maps.

  Opts:

    * `:accepted_algs` - the JOSE algorithms a candidate trusted key may use.
      Defaults to `SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA over Ed25519,
      and explicit Ed25519). Supplying a list selects an explicit non-FAPI
      algorithm policy unless `:enforce_fapi_alg_policy` is also `true`.
    * `:enforce_fapi_alg_policy` - enforce the FAPI RSA modulus and Edwards
      curve restrictions in addition to `:accepted_algs`. Defaults to `true`
      when `:accepted_algs` is omitted and `false` when the caller supplies an
      explicit algorithm policy. Composed FAPI profiles that narrow the
      allowlist must pass `true`.
  """
  @spec verify(String.t(), String.t(), String.t() | [String.t()], map() | [map()] | map(), verify_opts()) ::
          {:ok, map()} | {:error, verify_error()}
  def verify(assertion, client_id, expected_audience, trusted_jwks, opts \\ [])

  def verify(assertion, client_id, expected_audience, trusted_jwks, opts)
      when is_binary(assertion) and is_binary(client_id) and is_list(opts) do
    with {:ok, header} <- peek_header(assertion),
         :ok <- check_crit(header),
         {:ok, claims} <- verify_signature(assertion, header, trusted_jwks, opts),
         :ok <- check_client_id(claims, client_id),
         :ok <- check_audience(claims, expected_audience),
         :ok <- check_expiry(claims, opts),
         :ok <- check_iat(claims, opts),
         :ok <- check_jti(claims) do
      {:ok, claims}
    end
  end

  def verify(_assertion, _client_id, _expected_audience, _trusted_jwks, _opts), do: {:error, :invalid_assertion}

  defp verify_signature(assertion, header, trusted_jwks, opts) do
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())

    enforce_fapi_policy =
      Keyword.get(opts, :enforce_fapi_alg_policy, not Keyword.has_key?(opts, :accepted_algs))

    candidates =
      JWS.verification_candidates(trusted_jwks,
        kid: Map.get(header, "kid"),
        accepted_algs: accepted_algs,
        fapi?: enforce_fapi_policy,
        malformed_key: :reject_set
      )

    JWS.verify_strict(assertion, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_assertion
    )
  end

  defp check_client_id(%{"iss" => id, "sub" => id}, id), do: :ok
  defp check_client_id(_claims, _client_id), do: {:error, :invalid_client_id}

  # FAPI 2 requires a single-valued string `aud`. An array audience is
  # rejected even when it contains an accepted value, and the string must
  # match one of the expected audiences exactly.
  defp check_audience(%{"aud" => aud}, expected) do
    if Claims.audience_matches?(aud, expected, :scalar_only),
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) and exp >= 0 do
    now = NumericDate.now(opts, default: :system, invalid_override: :fallback)

    if NumericDate.not_expired?(exp, now, leeway: 0),
      do: check_max_lifetime(exp, now, opts),
      else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: {:error, :expired}

  defp check_max_lifetime(exp, now, opts) do
    case Keyword.get(opts, :max_lifetime) do
      n when is_integer(n) and n > 0 ->
        if NumericDate.within_lifetime?(exp, now, n), do: :ok, else: {:error, :invalid_assertion}

      _ ->
        :ok
    end
  end

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    if NumericDate.not_before_reached?(
         iat,
         NumericDate.now(opts, default: :system, invalid_override: :fallback),
         skew: @clock_skew_seconds
       ),
       do: :ok,
       else: {:error, :not_yet_valid}
  end

  defp check_iat(%{"iat" => _}, _opts), do: {:error, :not_yet_valid}
  defp check_iat(_claims, _opts), do: :ok

  defp check_jti(%{"jti" => jti}) when is_binary(jti) and jti != "", do: :ok
  defp check_jti(_claims), do: {:error, :missing_jti}

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp peek_header(jwt), do: peek_json(jwt, :protected)
  defp peek_payload(jwt), do: peek_json(jwt, :payload)

  defp peek_json(jwt, segment) do
    case JWS.peek_json(jwt, segment) do
      {:ok, map} -> {:ok, map}
      {:error, _reason} -> {:error, :invalid_assertion}
    end
  end
end
