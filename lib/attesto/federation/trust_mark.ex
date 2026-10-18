defmodule Attesto.Federation.TrustMark do
  @moduledoc """
  Verify an OpenID Federation 1.0 Trust Mark JWT.

  `Attesto.Federation.EntityStatement`'s `trust_marks` handling only checks
  that each entry is *shaped* correctly (non-empty `trust_mark_type` and
  `trust_mark` JWT string) - it never verifies the `trust_mark` JWT itself.
  This module does that verification: signature, `typ`, `crit`, and the
  trust mark's own claims (`iss`, `sub`, `trust_mark_type`, `iat`, `exp`).

  A Trust Mark JWT is signed by a Trust Mark Issuer over claims that at
  minimum name the entity it was issued to (`sub`), the Trust Mark Issuer
  itself (`iss`), and which mark it asserts (`trust_mark_type`). The caller
  supplies the Trust Mark Issuer's JWK Set - obtained and trusted out of
  band (e.g. that issuer's own Entity Configuration, itself resolved and
  trust-chain-verified), exactly as `EntityStatement.verify/3` requires
  trusted signer keys from its caller rather than trusting embedded keys.

  Conn-free and fail-closed, like the rest of attesto core.
  """

  alias Attesto.{JWS, NumericDate, SigningAlg}

  @typ "trust-mark+jwt"
  @max_trust_mark_bytes 64 * 1_024

  @type verify_error ::
          :invalid_trust_mark
          | :invalid_typ
          | :invalid_alg
          | :unsupported_critical_header
          | :invalid_signature
          | :not_yet_valid
          | :expired

  @doc """
  Verify a Trust Mark JWT's signature and claims.

  `trusted_jwks` is the Trust Mark Issuer's JWK Set (`%{"keys" => [...]}`, a
  single JWK map, or a list), trusted by the caller out of band - this
  function never trusts keys embedded in the token itself. Options:

    * `:accepted_algs` - JWS algorithms accepted for the signature. Defaults
      to `Attesto.SigningAlg.allowed/0`.
    * `:issuer` - if given, the verified `iss` must equal it (the expected
      Trust Mark Issuer).
    * `:subject` - required. The verified `sub` must equal this entity; a
      Trust Mark is never accepted without binding it to its intended holder.
    * `:trust_mark_type` - if given, the verified `trust_mark_type` must
      equal it (the mark the caller asked about).
    * `:now` / `:leeway` - clock reference and skew for the required `iat`
      and optional `exp` checks. Revocation may instead be checked via the
      Trust Mark Issuer's status endpoint, which is out of scope here.

  Returns `{:ok, claims}` with the trust mark's full claim set on success, or
  `{:error, reason}` - a tampered signature, wrong key, expired mark, or a
  mismatch against any `:issuer`/`:subject`/`:trust_mark_type` all fail
  closed.
  """
  @spec verify(String.t(), map() | [map()] | list(), keyword()) ::
          {:ok, map()} | {:error, verify_error()}
  def verify(trust_mark_jwt, trusted_jwks, opts \\ [])

  def verify(trust_mark_jwt, trusted_jwks, opts) when is_binary(trust_mark_jwt) and is_list(opts) do
    with :ok <- require_subject(opts),
         {:ok, header} <-
           JWS.protected_header(trust_mark_jwt,
             error: :invalid_trust_mark,
             crit_error: :unsupported_critical_header,
             max_compact_bytes: @max_trust_mark_bytes
           ),
         :ok <- check_typ(header),
         :ok <- check_alg(header, opts),
         :ok <- check_kid(header),
         {:ok, claims} <- verify_signature(trust_mark_jwt, header, trusted_jwks, opts),
         :ok <- validate_claims(claims, opts) do
      {:ok, claims}
    end
  end

  def verify(_trust_mark_jwt, _trusted_jwks, _opts), do: {:error, :invalid_trust_mark}

  defp require_subject(opts) do
    case Keyword.get(opts, :subject) do
      subject when is_binary(subject) and subject != "" -> :ok
      _missing_or_invalid -> {:error, :invalid_trust_mark}
    end
  end

  defp check_typ(%{"typ" => @typ}), do: :ok
  defp check_typ(_header), do: {:error, :invalid_typ}

  defp check_alg(%{"alg" => alg}, opts) when is_binary(alg) do
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    if alg != "none" and alg in SigningAlg.allowed() and is_list(accepted_algs) and alg in accepted_algs,
      do: :ok,
      else: {:error, :invalid_alg}
  end

  defp check_alg(_header, _opts), do: {:error, :invalid_alg}

  defp check_kid(%{"kid" => kid}) when is_binary(kid) and kid != "", do: :ok
  defp check_kid(_header), do: {:error, :invalid_trust_mark}

  defp verify_signature(jwt, header, jwks, opts) do
    JWS.verify_trusted(jwt, header, jwks,
      accepted_algs: Keyword.get(opts, :accepted_algs, SigningAlg.allowed()),
      malformed_key: :reject_set,
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_trust_mark,
      claims_map?: true
    )
  end

  defp validate_claims(claims, opts) do
    with :ok <- validate_required_claims(claims),
         :ok <- validate_expected(claims, opts) do
      validate_temporal_claims(claims, opts)
    end
  end

  defp validate_required_claims(claims) do
    if non_empty_string?(Map.get(claims, "iss")) and
         non_empty_string?(Map.get(claims, "sub")) and
         non_empty_string?(Map.get(claims, "trust_mark_type")) and
         NumericDate.valid?(Map.get(claims, "iat"), non_negative: true) do
      :ok
    else
      {:error, :invalid_trust_mark}
    end
  end

  defp non_empty_string?(value), do: is_binary(value) and value != ""

  defp validate_expected(claims, opts) do
    if expected_claim?(claims, "iss", Keyword.get(opts, :issuer)) and
         expected_claim?(claims, "sub", Keyword.get(opts, :subject)) and
         expected_claim?(claims, "trust_mark_type", Keyword.get(opts, :trust_mark_type)) do
      :ok
    else
      {:error, :invalid_trust_mark}
    end
  end

  defp expected_claim?(_claims, _claim, nil), do: true
  defp expected_claim?(claims, claim, expected), do: Map.get(claims, claim) == expected

  defp validate_temporal_claims(claims, opts) do
    now = NumericDate.now(opts, default: :system, invalid_override: :fallback)
    leeway = Keyword.get(opts, :leeway, 0)

    cond do
      not (is_integer(leeway) and leeway >= 0) ->
        {:error, :invalid_trust_mark}

      not NumericDate.not_before_reached?(claims["iat"], now, skew: leeway) ->
        {:error, :not_yet_valid}

      Map.has_key?(claims, "exp") and
          not NumericDate.not_expired?(claims["exp"], now, leeway: leeway) ->
        {:error, :expired}

      true ->
        :ok
    end
  end
end
