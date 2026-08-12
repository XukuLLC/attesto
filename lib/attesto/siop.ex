defmodule Attesto.Siop do
  @moduledoc """
  SIOPv2 Self-Issued ID Token verification for the Relying Party role.

  A Self-Issued ID Token is not verified against an issuer-owned JWKS. The
  holder either embeds a public key in `sub_jwk` and uses its RFC 7638 SHA-256
  thumbprint as `sub`, or uses a self-contained `did:jwk` / `did:key` subject
  whose resolved verification method signs the token. `verify/2` ties the
  subject, verification key, and signature together before returning the
  verified subject and public key.

  This module implements the JWK Thumbprint Subject Syntax Type from
  Self-Issued OpenID Provider v2 draft 13, section 11.1. It accepts `sub_jwk`
  in the payload, as the current draft specifies, and in the protected JOSE
  header for wallet interoperability. If both locations are present, their
  JWK maps must be identical.

  The current draft identifies a Self-Issued ID Token with `iss == sub`.
  `https://self-issued.me/v2`, used by the earlier static-discovery model, is
  also accepted for JWK-thumbprint subjects. DID subjects require `iss == sub`
  and a protected `kid` naming the method-defined verification method. Only
  connection-free `did:jwk` and `did:key` are resolved here; network-backed DID
  methods remain host-owned and fail closed.

  Verification is conn-free and fail-closed:

    * the compact JWS must be canonical and carry no unsupported critical
      headers;
    * `alg` must be an Attesto-supported asymmetric algorithm allowed by RP
      policy and compatible with a public verification JWK;
    * the signature must verify strictly with the embedded or DID-resolved
      holder key;
    * `sub` must exactly equal the key's RFC 7638 thumbprint, or be the
      `did:jwk` / `did:key` from which the key and protected `kid` are derived;
    * `iss` must equal `sub` for DID subjects, or either `sub` or
      `https://self-issued.me/v2` for JWK-thumbprint subjects;
    * `aud` must contain the RP Client ID and `nonce` must exactly match the
      Authentication Request;
    * `exp` and `iat` are required non-negative NumericDates; `nbf` is optional
      but, when present, must also be a non-negative NumericDate. Expired and
      not-yet-valid tokens are rejected.

  Claims other than the cryptographically bound `sub` remain self-attested.
  """

  alias Attesto.{Claims, Did, JWS, Key, NumericDate, SecureCompare, SigningAlg, Thumbprint}

  @self_issued_issuer "https://self-issued.me/v2"
  @header_typ "JWT"
  @clock_skew_seconds 60

  @type verified :: %{subject: String.t(), jwk: map()}

  @type verify_opts :: [
          {:audience, String.t()}
          | {:nonce, String.t()}
          | {:now, DateTime.t() | non_neg_integer()}
          | {:accepted_algs, [SigningAlg.alg()]}
        ]

  @type verify_error ::
          :invalid_token
          | :unsupported_critical_header
          | :unexpected_typ
          | :invalid_alg
          | :missing_sub_jwk
          | :invalid_sub_jwk
          | :invalid_signature
          | :invalid_subject
          | :invalid_issuer
          | :invalid_audience
          | :invalid_nonce
          | :invalid_claims
          | :expired
          | :not_yet_valid

  @doc """
  Verify a Self-Issued ID Token and return its subject and holder public JWK.

  JWK-thumbprint subjects may carry `sub_jwk` in the payload or protected
  header. A `did:jwk` subject must instead carry protected `kid` equal to
  `did:jwk:...#0`; a `did:key` subject must carry protected `kid` equal to the
  DID followed by `#` and its multibase value. A DID response containing
  `sub_jwk`, omitting `kid`, or naming any other verification method is
  rejected.

  Required options:

    * `:audience` - the RP Client ID sent in the Authentication Request. The
      token's `aud` may be this string or an all-string array containing it.
    * `:nonce` - the nonce sent in the Authentication Request. SIOPv2 requires
      it to be present and identical in the Self-Issued ID Token.

  Optional options:

    * `:now` - clock reference as a `DateTime` or Unix seconds.
    * `:accepted_algs` - holder signature algorithms accepted by RP policy.
      Defaults to `Attesto.SigningAlg.allowed/0`; `none`, MAC algorithms, and
      algorithms unsupported by Attesto remain rejected even if listed.

  The convenience `verify/3` form accepts `id_token`, `audience`, and `nonce`
  as positional arguments and applies the default clock and algorithm policy.
  """
  @spec verify(String.t(), verify_opts()) :: {:ok, verified()} | {:error, verify_error()}
  def verify(id_token, opts) when is_binary(id_token) and is_list(opts) do
    with {:ok, audience} <- required_option(opts, :audience, :invalid_audience),
         {:ok, nonce} <- required_option(opts, :nonce, :invalid_nonce),
         {:ok, header} <- peek_json(id_token, :protected),
         :ok <- check_crit(header),
         :ok <- check_typ(header),
         {:ok, alg} <- check_alg(header, opts),
         {:ok, unverified_claims} <- peek_json(id_token, :payload),
         {:ok, binding} <- resolve_subject_binding(header, unverified_claims, alg),
         {:ok, claims} <- verify_signature(id_token, alg, binding.jwk),
         :ok <- check_verified_subject_binding(header, claims, binding, alg),
         {:ok, subject} <- check_subject(claims, binding),
         :ok <- check_issuer(claims, subject, binding.type),
         :ok <- check_audience(claims, audience),
         :ok <- check_nonce(claims, nonce),
         :ok <- check_temporal(claims, NumericDate.now(opts)) do
      {:ok, %{subject: subject, jwk: binding.jwk_map}}
    end
  end

  def verify(_id_token, _opts), do: {:error, :invalid_token}

  @doc """
  Verify a Self-Issued ID Token against an RP Client ID and request nonce.
  """
  @spec verify(String.t(), String.t(), String.t()) :: {:ok, verified()} | {:error, verify_error()}
  def verify(id_token, audience, nonce) do
    verify(id_token, audience: audience, nonce: nonce)
  end

  # ── JOSE header and embedded key ─────────────────────────────────────────

  defp peek_json(id_token, segment) do
    case JWS.peek_json(id_token, segment) do
      {:ok, map} -> {:ok, map}
      {:error, _reason} -> {:error, :invalid_token}
    end
  end

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp check_typ(%{"typ" => @header_typ}), do: :ok
  defp check_typ(%{"typ" => _other}), do: {:error, :unexpected_typ}
  defp check_typ(_header), do: :ok

  defp check_alg(%{"alg" => alg}, opts) when is_binary(alg) do
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    if is_list(accepted_algs) and alg in accepted_algs and alg in SigningAlg.allowed(),
      do: {:ok, alg},
      else: {:error, :invalid_alg}
  end

  defp check_alg(_header, _opts), do: {:error, :invalid_alg}

  defp resolve_subject_binding(header, %{"sub" => "did:" <> _rest = subject} = claims, alg) do
    with :ok <- reject_did_sub_jwk(header, claims),
         {:ok, verification_method} <- local_did_verification_method(subject),
         :ok <- check_did_kid(header, verification_method),
         {:ok, jwk_map} <- resolve_local_did(subject),
         {:ok, jwk} <- verification_jwk(jwk_map, alg, :invalid_subject) do
      {:ok, %{type: :did, subject: subject, jwk_map: jwk_map, jwk: jwk}}
    end
  end

  defp resolve_subject_binding(header, claims, alg) do
    with {:ok, jwk_map} <- select_sub_jwk(header, claims),
         {:ok, jwk} <- verification_jwk(jwk_map, alg) do
      {:ok,
       %{
         type: :jwk_thumbprint,
         subject: Map.get(claims, "sub"),
         jwk_map: jwk_map,
         jwk: jwk
       }}
    end
  end

  defp reject_did_sub_jwk(header, claims) do
    if Map.has_key?(header, "sub_jwk") or Map.has_key?(claims, "sub_jwk"),
      do: {:error, :invalid_sub_jwk},
      else: :ok
  end

  defp local_did_verification_method("did:jwk:" <> encoded = did) when encoded != "", do: {:ok, did <> "#0"}

  defp local_did_verification_method("did:key:" <> multibase = did) when multibase != "",
    do: {:ok, did <> "#" <> multibase}

  defp local_did_verification_method(_subject), do: {:error, :invalid_subject}

  defp check_did_kid(%{"kid" => expected}, expected), do: :ok
  defp check_did_kid(_header, _expected), do: {:error, :invalid_subject}

  defp resolve_local_did(subject) do
    case Did.resolve(subject) do
      {:ok, jwk_map} when is_map(jwk_map) -> {:ok, jwk_map}
      _unsupported_or_invalid -> {:error, :invalid_subject}
    end
  end

  defp select_sub_jwk(header, claims) do
    case {Map.fetch(header, "sub_jwk"), Map.fetch(claims, "sub_jwk")} do
      {:error, :error} ->
        {:error, :missing_sub_jwk}

      {{:ok, header_jwk}, :error} ->
        present_sub_jwk(header_jwk)

      {:error, {:ok, claim_jwk}} ->
        present_sub_jwk(claim_jwk)

      {{:ok, same_jwk}, {:ok, same_jwk}} ->
        present_sub_jwk(same_jwk)

      {{:ok, _header_jwk}, {:ok, _claim_jwk}} ->
        {:error, :invalid_sub_jwk}
    end
  end

  defp present_sub_jwk(jwk_map) when is_map(jwk_map) and map_size(jwk_map) > 0, do: {:ok, jwk_map}
  defp present_sub_jwk(_jwk_map), do: {:error, :invalid_sub_jwk}

  defp verification_jwk(jwk_map, alg, error \\ :invalid_sub_jwk) do
    with {:ok, jwk} <- Key.verification_jwk(jwk_map, alg: alg),
         ^alg <- SigningAlg.validate_for_key!(alg, jwk) do
      {:ok, jwk}
    else
      _other -> {:error, error}
    end
  rescue
    _ -> {:error, error}
  catch
    _, _ -> {:error, error}
  end

  # The payload was inspected before signature verification solely to obtain
  # the verification key. Resolve the subject binding again from JOSE's
  # verified claim map and require exact equality so parser differences cannot
  # swap either an embedded key or a DID subject.
  defp check_verified_subject_binding(header, claims, used, alg) do
    case resolve_subject_binding(header, claims, alg) do
      {:ok,
       %{
         type: used_type,
         subject: used_subject,
         jwk_map: used_jwk_map
       }}
      when used_type == used.type and used_subject == used.subject and used_jwk_map == used.jwk_map ->
        :ok

      {:ok, _other_binding} ->
        {:error, binding_error(used.type)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp binding_error(:did), do: :invalid_subject
  defp binding_error(:jwk_thumbprint), do: :invalid_sub_jwk

  defp verify_signature(id_token, alg, jwk) do
    JWS.verify_strict(id_token, [{nil, alg, jwk}],
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_token,
      claims_map?: true
    )
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp thumbprint(jwk) do
    case Thumbprint.of_jwk(jwk) do
      {:ok, thumbprint} -> {:ok, thumbprint}
      {:error, :malformed_jwk} -> {:error, :invalid_sub_jwk}
    end
  end

  # ── Self-Issued ID Token claims ──────────────────────────────────────────

  defp check_subject(%{"sub" => subject}, %{type: :did, subject: subject}) when is_binary(subject) and subject != "",
    do: {:ok, subject}

  defp check_subject(claims, %{type: :jwk_thumbprint, jwk: jwk}) do
    with {:ok, thumbprint} <- thumbprint(jwk) do
      check_thumbprint_subject(claims, thumbprint)
    end
  end

  defp check_subject(_claims, _binding), do: {:error, :invalid_subject}

  defp check_thumbprint_subject(%{"sub" => subject}, thumbprint) when is_binary(subject) and subject != "" do
    if SecureCompare.equal?(subject, thumbprint),
      do: {:ok, subject},
      else: {:error, :invalid_subject}
  end

  defp check_thumbprint_subject(_claims, _thumbprint), do: {:error, :invalid_subject}

  defp check_issuer(%{"iss" => subject}, subject, :did), do: :ok

  defp check_issuer(%{"iss" => issuer}, subject, :jwk_thumbprint)
       when issuer == @self_issued_issuer or issuer == subject, do: :ok

  defp check_issuer(_claims, _subject, _type), do: {:error, :invalid_issuer}

  defp check_audience(%{"aud" => audience}, expected) do
    if Claims.audience_matches?(audience, expected, :array),
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  defp check_nonce(%{"nonce" => nonce}, expected) when is_binary(nonce) do
    if SecureCompare.equal?(nonce, expected),
      do: :ok,
      else: {:error, :invalid_nonce}
  end

  defp check_nonce(_claims, _expected), do: {:error, :invalid_nonce}

  defp check_temporal(claims, now) do
    with :ok <- check_exp(claims, now),
         :ok <- check_iat(claims, now) do
      check_nbf(claims, now)
    end
  end

  defp check_exp(claims, now) do
    case NumericDate.fetch(claims, "exp", required: true, non_negative: true) do
      {:ok, exp} ->
        if NumericDate.not_expired?(exp, now, leeway: 0),
          do: :ok,
          else: {:error, :expired}

      _missing_or_invalid ->
        {:error, :expired}
    end
  end

  defp check_iat(claims, now) do
    case NumericDate.fetch(claims, "iat", required: true, non_negative: true) do
      {:ok, iat} ->
        if NumericDate.not_before_reached?(iat, now, skew: @clock_skew_seconds),
          do: :ok,
          else: {:error, :not_yet_valid}

      _missing_or_invalid ->
        {:error, :invalid_claims}
    end
  end

  defp check_nbf(claims, now) do
    case NumericDate.fetch(claims, "nbf", required: false, non_negative: true) do
      :missing ->
        :ok

      {:ok, nbf} ->
        if NumericDate.not_before_reached?(nbf, now, skew: @clock_skew_seconds),
          do: :ok,
          else: {:error, :not_yet_valid}

      {:error, _reason} ->
        {:error, :invalid_claims}
    end
  end

  defp required_option(opts, key, error) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _other -> {:error, error}
    end
  end
end
