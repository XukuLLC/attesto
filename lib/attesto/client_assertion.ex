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
    * `nbf`, when present, has been reached within the permitted clock skew
    * `exp` is not earlier than a present `iat` or `nbf`
    * `jti` is present, non-empty, and at most 256 bytes for replay tracking
      by the caller

  The JOSE algorithm is resolved from the trusted JWK's `alg` member when
  present, otherwise from the key shape. It is never accepted just because the
  presented JWT header names it.
  """

  alias Attesto.{Claims, JWS}
  alias Attesto.NumericDate
  alias Attesto.Options
  alias Attesto.SigningAlg

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @clock_skew_seconds NumericDate.default_clock_skew_seconds()
  @default_max_lifetime_seconds 300
  @max_jti_bytes 256
  @accepted_typ [nil, "JWT", "client-authentication+jwt"]
  @authorization_request_claims ~w(response_type redirect_uri code_challenge request request_uri)

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:max_lifetime, pos_integer() | :unbounded}
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

    * `:max_lifetime` - maximum remaining assertion lifetime in seconds,
      measured from verification time to `exp`. Defaults to 300. Set
      `:unbounded` only when the deployment deliberately applies its own
      assertion-lifetime policy.
    * `:accepted_algs` - the JOSE algorithms a candidate trusted key may use.
      Defaults to `SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA over Ed25519,
      and explicit Ed25519). An empty list always denies all algorithms.
    * `:enforce_fapi_alg_policy` - enforce the FAPI RSA modulus and Edwards
      curve restrictions in addition to `:accepted_algs`. Defaults to `true`
      for every algorithm allowlist. Only explicit `false` relaxes
      these gates.
  """
  @spec verify(String.t(), String.t(), String.t() | [String.t()], map() | [map()] | map(), verify_opts()) ::
          {:ok, map()} | {:error, verify_error()}
  def verify(assertion, client_id, expected_audience, trusted_jwks, opts \\ [])

  def verify(assertion, client_id, expected_audience, trusted_jwks, opts)
      when is_binary(assertion) and is_binary(client_id) and is_list(opts) do
    opts = validate_policy_options!(opts)

    with {:ok, header} <-
           JWS.protected_header(assertion,
             error: :invalid_assertion,
             crit_error: :unsupported_critical_header
           ),
         :ok <- check_typ(header),
         {:ok, claims} <- verify_signature(assertion, header, trusted_jwks, opts),
         :ok <- reject_authorization_request_claims(claims),
         :ok <- check_client_id(claims, client_id),
         :ok <- check_audience(claims, expected_audience),
         :ok <- check_expiry(claims, opts),
         :ok <- check_iat(claims, opts),
         :ok <- check_nbf(claims, opts),
         :ok <- check_temporal_order(claims),
         :ok <- check_jti(claims) do
      {:ok, claims}
    end
  end

  def verify(_assertion, _client_id, _expected_audience, _trusted_jwks, _opts), do: {:error, :invalid_assertion}

  defp verify_signature(assertion, header, trusted_jwks, opts) do
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())

    enforce_fapi_policy =
      Keyword.fetch!(opts, :enforce_fapi_alg_policy)

    JWS.verify_trusted(assertion, header, trusted_jwks,
      accepted_algs: accepted_algs,
      fapi?: enforce_fapi_policy,
      malformed_key: :reject_set,
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_assertion
    )
  end

  defp validate_policy_options!(opts) do
    enforce_fapi_policy =
      Options.boolean!(opts, :enforce_fapi_alg_policy, SigningAlg.default_fapi_policy?())

    case Keyword.fetch(opts, :max_lifetime) do
      :error -> :ok
      {:ok, :unbounded} -> :ok
      {:ok, value} when is_integer(value) and value > 0 -> :ok
      {:ok, _invalid} -> raise ArgumentError, ":max_lifetime must be a positive integer or :unbounded"
    end

    Keyword.put(opts, :enforce_fapi_alg_policy, enforce_fapi_policy)
  end

  defp check_client_id(%{"iss" => id, "sub" => id}, id) when is_binary(id) and id != "", do: :ok
  defp check_client_id(_claims, _client_id), do: {:error, :invalid_client_id}

  defp check_typ(header) do
    if Claims.typ_matches?(Map.get(header, "typ"), @accepted_typ, normalization: :application_subtype),
      do: :ok,
      else: {:error, :invalid_assertion}
  end

  defp reject_authorization_request_claims(claims) do
    if Enum.any?(@authorization_request_claims, &Map.has_key?(claims, &1)),
      do: {:error, :invalid_assertion},
      else: :ok
  end

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
    case Keyword.get(opts, :max_lifetime, @default_max_lifetime_seconds) do
      n when is_integer(n) and n > 0 ->
        if NumericDate.within_lifetime?(exp, now, n), do: :ok, else: {:error, :invalid_assertion}

      :unbounded ->
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

  defp check_nbf(%{"nbf" => nbf}, opts) when is_integer(nbf) and nbf >= 0 do
    if NumericDate.not_before_reached?(
         nbf,
         NumericDate.now(opts, default: :system, invalid_override: :fallback),
         skew: @clock_skew_seconds
       ),
       do: :ok,
       else: {:error, :not_yet_valid}
  end

  defp check_nbf(%{"nbf" => _}, _opts), do: {:error, :not_yet_valid}
  defp check_nbf(_claims, _opts), do: :ok

  defp check_temporal_order(%{"exp" => exp, "iat" => iat}) when is_integer(exp) and is_integer(iat) and exp < iat,
    do: {:error, :invalid_assertion}

  defp check_temporal_order(%{"exp" => exp, "nbf" => nbf}) when is_integer(exp) and is_integer(nbf) and exp < nbf,
    do: {:error, :invalid_assertion}

  defp check_temporal_order(_claims), do: :ok

  defp check_jti(%{"jti" => jti}) when is_binary(jti) and jti != "" do
    if byte_size(jti) <= @max_jti_bytes, do: :ok, else: {:error, :invalid_assertion}
  end

  defp check_jti(_claims), do: {:error, :missing_jti}

  defp peek_payload(jwt), do: peek_json(jwt, :payload)

  defp peek_json(jwt, segment) do
    case JWS.peek_json(jwt, segment) do
      {:ok, map} -> {:ok, map}
      {:error, _reason} -> {:error, :invalid_assertion}
    end
  end
end
