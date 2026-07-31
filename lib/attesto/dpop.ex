defmodule Attesto.DPoP do
  @moduledoc """
  RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP).

  A DPoP proof is a JWS that a client signs with a key it holds and
  attaches to a token request (`POST /token`) or to every
  protected-resource request that uses a DPoP-bound access token. The
  proof carries:

    * a JOSE header with `typ: "dpop+jwt"`, an asymmetric signature
      `alg`, and the client's public key in `jwk`;
    * a JOSE payload with `htm` (HTTP method), `htu` (HTTP target URI),
      `iat` (creation timestamp), `jti` (unique replay identifier), and -
      when presented alongside an access token - `ath`, the
      base64url-encoded SHA-256 hash of that access token.

  The server validates the proof against the live request, computes the
  RFC 7638 SHA-256 thumbprint of the embedded JWK, and uses the
  thumbprint to bind issued/presented access tokens to the proof key via
  the access token's `cnf.jkt` claim (RFC 7800).

  This module verifies a single DPoP proof and returns the thumbprint and
  replay identifier so the caller (the token endpoint or the
  authenticated-request handler) can:

    * compare `jkt` to the bound access token's `cnf.jkt`, and
    * persist `jti` in a replay cache.

  It is framework-agnostic: no Plug, no database, no application config.
  It is a pure function of the proof JWT, the HTTP request context, and
  an optional access token. A resource server composes
  `Attesto.Token.verify/3` with this module's `verify_proof/2`.

  ## Accepted algorithms

  Per RFC 9449 §4.2, DPoP proofs MUST be signed with an asymmetric
  algorithm. This verifier whitelists `ES256`, `ES384`, `ES512`, `RS256`,
  `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, legacy `EdDSA`, and RFC 9864
  `Ed25519` / `Ed448`, intersected with the algorithms the configured JOSE
  backend reports as available. The explicit Edwards identifiers must match
  the embedded public JWK's curve, and RSA proof keys must have a modulus of
  at least 2048 bits. Symmetric algorithms (`HS*`) and the unsecured `none`
  algorithm are rejected; there is no caller-facing knob to relax this.

  ## Replay protection

  RFC 9449 §11.1 requires the resource server to reject a DPoP proof it
  has already seen. A captured-and-replayed proof is otherwise good for
  the entire `iat` acceptance window (default 60 seconds). This verifier
  enforces replay protection in two layers:

    1. The proof's `jti` is length-capped (see `@max_jti_length`) so an
      attacker cannot exhaust the cache by submitting proofs with
      megabyte-sized `jti` values.
    2. If the caller supplies the `:replay_check` opt, the verifier
      invokes it with the proof's `jti` AND the TTL the cache must remember
      it for (the acceptance window: `max_age_seconds` + future skew),
      AFTER every other check has passed (so an attacker cannot fill the
      cache with proofs that would have failed anyway). Deriving the TTL
      from the verifier's age policy keeps the cache from forgetting a
      `jti` while the proof is still acceptable. The callback returns `:ok`
      or `{:error, :replay}`. `Attesto.DPoP.ReplayCache` provides a default
      ETS-backed implementation (`check_and_record/2`).

  Protected-resource pipelines MUST pass `:replay_check`. Leaving it out
  is acceptable only in test scaffolding and at the token endpoint on
  first use of a proof (the endpoint records the `jti` itself).
  """

  alias Attesto.SecureCompare
  alias Attesto.SigningAlg
  alias Attesto.Thumbprint

  # RFC 9449 §4.2: asymmetric algorithms only.
  @allowed_algs ~w(ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519 Ed448)
  @rsa_algs ~w(RS256 RS384 RS512 PS256 PS384 PS512)
  @minimum_rsa_modulus_bits 2048
  @proof_typ "dpop+jwt"
  @default_max_age_seconds 60
  # Match the verifier-wide clock skew used for JWT assertions and ID/access
  # tokens. DPoP proofs are still short-lived by `@default_max_age_seconds`;
  # this only tolerates clients whose clocks are slightly ahead of the server.
  @future_skew_seconds 60
  # RFC 9449 places no upper bound on `jti` length, but the replay cache
  # holds every `jti` for the entire acceptance window. A malicious
  # client could exhaust memory with megabyte-sized values; cap at 256
  # bytes (a UUID is 36, a 256-bit b64url id is 43, so the cap is
  # generous for any legitimate scheme).
  @max_jti_length 256

  @type replay_check_fun :: (String.t(), pos_integer() -> :ok | {:error, :replay})
  @type nonce_check_fun :: (String.t() | nil -> :ok | {:error, :use_dpop_nonce})

  @type verify_opts :: [
          {:http_method, String.t()}
          | {:http_uri, String.t()}
          | {:access_token, String.t() | nil}
          | {:now, DateTime.t() | non_neg_integer()}
          | {:max_age_seconds, pos_integer()}
          | {:replay_check, replay_check_fun() | nil}
          | {:nonce_check, nonce_check_fun() | nil}
        ]

  @type verified_proof :: %{
          ath: String.t() | nil,
          htm: String.t(),
          htu: String.t(),
          iat: non_neg_integer(),
          jkt: String.t(),
          jti: String.t(),
          replay_ttl: pos_integer()
        }

  @type verify_error ::
          :invalid_proof
          | :invalid_signature
          | :invalid_typ
          | :invalid_alg
          | :unsupported_critical_header
          | :missing_jwk
          | :invalid_jwk
          | :invalid_htm
          | :invalid_htu
          | :missing_jti
          | :invalid_jti
          | :missing_ath
          | :invalid_ath
          | :missing_iat
          | :invalid_iat
          | :proof_expired
          | :replay
          | :use_dpop_nonce

  @doc """
  Verify a DPoP proof JWS per RFC 9449 against the given request context.

  ## Required opts

    * `:http_method` - the HTTP method of the request the proof was
      attached to (`"POST"`, `"GET"`, …). Compared case-sensitively to
      the proof's `htm` claim per RFC 9449 §4.3.
    * `:http_uri` - the HTTP target URI of the request, including scheme
      and host. Query and fragment components are stripped before
      comparison so a client that signed `https://api.example/x` and the
      server-observed `https://api.example/x?cb=1` still match.

  ## Optional opts

    * `:access_token` - the bearer/DPoP access token presented on the
      same request. If supplied, the proof MUST carry an `ath` claim
      whose value is `base64url(SHA-256(access_token))` per RFC 9449
      §4.3. If `:access_token` is omitted (e.g. the proof is attached to
      a token endpoint request, where no access token exists yet), the
      `ath` claim - if present - is returned but not constrained.
    * `:now` - `DateTime` or unix-seconds integer used as the clock
      reference. Defaults to `DateTime.utc_now/0`. Test-facing.
    * `:max_age_seconds` - how far in the past `iat` may be. Default 60.
      A constant #{@future_skew_seconds}-second window into the future is
      also accepted to tolerate modest client-side clock skew.
    * `:replay_check` - a two-arity function called with the proof's
      `jti` and the TTL (seconds) the store must remember it for, AFTER
      every other check has passed. Returns `:ok` if the `jti` has not
      been seen, or `{:error, :replay}` if it has. Required by
      protected-resource pipelines; pass
      `&Attesto.DPoP.ReplayCache.check_and_record/2`. Omit only in test
      scaffolding.
    * `:nonce_check` - a one-arity function called with the proof's
      `nonce` claim (which may be `nil`). Returns `:ok` or
      `{:error, :use_dpop_nonce}` (RFC 9449 §8), the latter telling the
      caller to answer with a fresh `DPoP-Nonce`. Omitted, no nonce is
      required. See `Attesto.DPoP.NonceStore`.

  ## Returns

    * `{:ok, %{jkt: ..., jti: ..., ath: ..., htm: ..., htu: ..., iat: ...}}`
      on success. `jkt` is the RFC 7638 SHA-256 thumbprint of the proof's
      embedded JWK; the caller compares it to the access token's
      `cnf.jkt`.
    * `{:error, reason}` otherwise. See the module typespecs for the full
      error set.
  """
  @spec verify_proof(String.t(), verify_opts()) ::
          {:ok, verified_proof()} | {:error, verify_error()}
  def verify_proof(proof, opts \\ [])

  def verify_proof(proof, opts) when is_binary(proof) and is_list(opts) do
    with {:ok, header} <- parse_header(proof),
         :ok <- check_typ(header),
         :ok <- check_alg(header),
         :ok <- check_crit(header),
         {:ok, jwk} <- extract_jwk(header),
         :ok <- check_key_strength(header["alg"], jwk),
         :ok <- check_edwards_alg_curve(header["alg"], jwk),
         {:ok, claims} <- verify_signature(proof, header["alg"], jwk),
         :ok <- check_htm(claims, opts),
         :ok <- check_htu(claims, opts),
         {:ok, iat} <- check_iat(claims, opts),
         {:ok, jti} <- check_jti(claims),
         {:ok, ath} <- check_ath(claims, opts),
         :ok <- check_nonce(claims, opts),
         :ok <- check_replay(jti, opts) do
      {:ok,
       %{
         ath: ath,
         htm: claims["htm"],
         htu: claims["htu"],
         iat: iat,
         jkt: JOSE.JWK.thumbprint(jwk),
         jti: jti,
         # The window this proof's `jti` must be remembered for, so a caller
         # that claims the identifier itself - rather than through
         # `:replay_check` here - uses the same acceptance window this
         # verification applied instead of deriving it a second time.
         replay_ttl: replay_ttl(opts)
       }}
    end
  end

  def verify_proof(_proof, _opts), do: {:error, :invalid_proof}

  @doc """
  RFC 7638 SHA-256 JWK thumbprint, base64url-encoded without padding.
  Accepts a `%JOSE.JWK{}` or a JWK as a plain map (e.g. the one in a DPoP
  proof's protected header).
  """
  @spec compute_jkt(JOSE.JWK.t() | map()) :: String.t()
  def compute_jkt(%JOSE.JWK{} = jwk), do: JOSE.JWK.thumbprint(jwk)

  def compute_jkt(map) when is_map(map) do
    map
    |> JOSE.JWK.from_map()
    |> JOSE.JWK.thumbprint()
  end

  @doc """
  The `ath` claim value defined by RFC 9449 §4.3:
  `base64url(SHA-256(access_token))`, unpadded.
  """
  @spec compute_ath(String.t()) :: String.t()
  def compute_ath(access_token) when is_binary(access_token), do: Thumbprint.of(access_token)

  @doc """
  Returns `true` iff the given access-token claims map advertises a DPoP
  binding via RFC 7800 `cnf.jkt`. Tolerates any verifier-accepted
  `cnf.jkt` value (non-empty string).
  """
  @spec dpop_bound?(map()) :: boolean()
  def dpop_bound?(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt) and jkt != "", do: true
  def dpop_bound?(_claims), do: false

  @doc """
  The list of JOSE `alg` values accepted on a DPoP proof's protected
  header, filtered by the configured JOSE backend's current capabilities.
  """
  @spec allowed_algs() :: [String.t()]
  def allowed_algs do
    supported = jose_jws_algs()
    Enum.filter(@allowed_algs, &(&1 in supported))
  end

  # ----- internal: header parsing -----

  # We pull the protected header out of the compact JWS ourselves rather
  # than letting `JOSE.JWT.verify_strict/3` do it: we need the embedded
  # `jwk` BEFORE we can verify the signature.
  defp parse_header(proof) do
    case String.split(proof, ".") do
      # Allow an empty signature segment: an `alg=none` "unsecured JWS"
      # has the literal compact form `<header>.<payload>.`. We parse the
      # header anyway so `check_alg/1` can reject it explicitly with
      # `:invalid_alg`, rather than collapsing the alg-confusion variant
      # into the opaque `:invalid_proof` bucket.
      [header_b64, _payload_b64, _sig_b64] when header_b64 != "" ->
        decode_header(header_b64)

      _ ->
        {:error, :invalid_proof}
    end
  end

  defp decode_header(b64) do
    with {:ok, bytes} <- url_decode(b64),
         {:ok, map} <- json_decode(bytes),
         true <- is_map(map) do
      {:ok, map}
    else
      _ -> {:error, :invalid_proof}
    end
  end

  # Strict, canonical, unpadded base64url (RFC 7515 §2): decode and require the
  # input to be the canonical encoding of the bytes (no padding, no
  # non-significant trailing bits). This matches the canonical-form check the
  # Token/IDToken/ClientAssertion/RequestObject verifiers apply, so the DPoP
  # header cannot be presented in a non-canonical/aliased form.
  defp url_decode(s) do
    case Base.url_decode64(s, padding: false) do
      {:ok, decoded} ->
        if Base.url_encode64(decoded, padding: false) == s, do: {:ok, decoded}, else: :error

      :error ->
        :error
    end
  end

  defp json_decode(bytes) do
    {:ok, JSON.decode!(bytes)}
  rescue
    _ -> :error
  end

  defp check_typ(%{"typ" => @proof_typ}), do: :ok
  defp check_typ(_header), do: {:error, :invalid_typ}

  defp check_alg(%{"alg" => alg}) when is_binary(alg) do
    if alg in allowed_algs(), do: :ok, else: {:error, :invalid_alg}
  end

  defp check_alg(_header), do: {:error, :invalid_alg}

  # RFC 7515 §4.1.11: a recipient that does not understand a JWS extension
  # named in `crit` MUST reject the JWS. A DPoP proof header that demands a
  # critical extension Attesto does not implement (Attesto implements none)
  # is rejected before the signature is trusted.
  defp check_crit(header) do
    if Map.has_key?(header, "crit"), do: {:error, :unsupported_critical_header}, else: :ok
  end

  defp extract_jwk(%{"jwk" => jwk} = header) when is_map(jwk) and map_size(jwk) > 0 do
    # RFC 9449 §4.2: the embedded JWK MUST be a public key for signing.
    # Reject any header that smuggles private-key material (accepting it
    # would still verify the signature but would leak the client's private
    # key into our logs / audit trail), any key whose own metadata
    # (RFC 7517 §4.2/§4.3 `use` / `key_ops`) marks it as not for signature
    # verification, and any key whose declared `alg` contradicts the JWS
    # header `alg`.
    cond do
      has_private_jwk_member?(jwk) -> {:error, :invalid_jwk}
      not usable_for_signing?(jwk) -> {:error, :invalid_jwk}
      not alg_consistent?(jwk, header) -> {:error, :invalid_jwk}
      true -> from_public_map(jwk)
    end
  end

  defp extract_jwk(_header), do: {:error, :missing_jwk}

  # RFC 7517 §4.4: if the JWK declares `alg`, it constrains the algorithm
  # the key may be used with, so a JWK `alg` that disagrees with the JWS
  # header `alg` is contradictory and rejected. An absent JWK `alg` imposes
  # no constraint.
  defp alg_consistent?(jwk, header) do
    case Map.get(jwk, "alg") do
      nil -> true
      alg -> alg == Map.get(header, "alg")
    end
  end

  defp from_public_map(jwk) do
    {:ok, JOSE.JWK.from_map(jwk)}
  rescue
    _ -> {:error, :invalid_jwk}
  catch
    _, _ -> {:error, :invalid_jwk}
  end

  defp check_edwards_alg_curve(alg, jwk) when alg in ["EdDSA", "Ed25519", "Ed448"] do
    SigningAlg.validate_for_key!(alg, jwk)
    :ok
  rescue
    _ -> {:error, :invalid_jwk}
  end

  defp check_edwards_alg_curve(_alg, _jwk), do: :ok

  defp check_key_strength(alg, jwk) when alg in @rsa_algs do
    case JOSE.JWK.to_public_map(jwk) do
      {_metadata, %{"kty" => "RSA"}} ->
        if SigningAlg.rsa_modulus_at_least?(jwk, @minimum_rsa_modulus_bits),
          do: :ok,
          else: {:error, :invalid_jwk}

      _other ->
        :ok
    end
  end

  defp check_key_strength(_alg, _jwk), do: :ok

  defp jose_jws_algs do
    case Keyword.get(JOSE.JWA.supports(), :jws) do
      {:alg, algorithms} when is_list(algorithms) -> algorithms
      _ -> []
    end
  rescue
    _ -> []
  end

  # Private-key components per RFC 7518 §6.2.2 / §6.3.2. Any of these in a
  # DPoP header is a protocol violation.
  @private_jwk_members ~w(d p q dp dq qi oth k)
  defp has_private_jwk_member?(jwk) do
    Enum.any?(@private_jwk_members, &Map.has_key?(jwk, &1))
  end

  # RFC 7517 §4.2/§4.3: if the key declares `use`, it must be "sig"; if it
  # declares `key_ops`, the list must allow "verify". A key explicitly
  # marked encryption-only must not be honoured to verify a proof
  # signature, even though the signature math might otherwise pass.
  defp usable_for_signing?(jwk) do
    use_ok? =
      case Map.get(jwk, "use") do
        nil -> true
        "sig" -> true
        _ -> false
      end

    ops_ok? =
      case Map.get(jwk, "key_ops") do
        nil -> true
        ops when is_list(ops) -> "verify" in ops
        _ -> false
      end

    use_ok? and ops_ok?
  end

  # ----- internal: signature verification -----

  defp verify_signature(proof, alg, jwk) do
    case JOSE.JWT.verify_strict(jwk, [alg], proof) do
      {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} when is_map(claims) ->
        {:ok, claims}

      {false, _jwt, _jws} ->
        {:error, :invalid_signature}

      _other ->
        # Same defensive pattern as `Attesto.Token`: JOSE collapses any
        # internal parser blow-up into a tuple we treat as opaque.
        {:error, :invalid_proof}
    end
  end

  # ----- internal: claim checks -----

  defp check_htm(%{"htm" => htm}, opts) when is_binary(htm) do
    expected = require_string!(opts, :http_method)
    if htm == expected, do: :ok, else: {:error, :invalid_htm}
  end

  defp check_htm(_claims, _opts), do: {:error, :invalid_htm}

  defp check_htu(%{"htu" => htu}, opts) when is_binary(htu) do
    expected = require_string!(opts, :http_uri)

    with {:ok, proof_uri} <- normalize_htu(htu),
         {:ok, expected_uri} <- normalize_htu(expected) do
      if proof_uri == expected_uri, do: :ok, else: {:error, :invalid_htu}
    end
  end

  defp check_htu(_claims, _opts), do: {:error, :invalid_htu}

  # RFC 9449 §4.3: compare the effective target URI without query/fragment.
  # URI scheme and host are case-insensitive, and an explicit HTTPS default
  # port is equivalent to an omitted port.
  defp normalize_htu(uri) do
    parsed = URI.parse(uri)
    scheme = parsed.scheme && String.downcase(parsed.scheme)
    host = parsed.host && String.downcase(parsed.host)

    cond do
      scheme != "https" -> {:error, :invalid_htu}
      is_nil(host) or host == "" -> {:error, :invalid_htu}
      not is_nil(parsed.userinfo) -> {:error, :invalid_htu}
      true -> {:ok, {scheme, host, normalize_htu_port(parsed.port), parsed.path || ""}}
    end
  rescue
    _ -> {:error, :invalid_htu}
  end

  defp normalize_htu_port(443), do: nil
  defp normalize_htu_port(port), do: port

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    now = unix_now(opts)
    max_age = Keyword.get(opts, :max_age_seconds, @default_max_age_seconds)

    cond do
      iat > now + @future_skew_seconds -> {:error, :invalid_iat}
      iat < now - max_age -> {:error, :proof_expired}
      true -> {:ok, iat}
    end
  end

  defp check_iat(%{"iat" => _}, _opts), do: {:error, :invalid_iat}
  defp check_iat(_claims, _opts), do: {:error, :missing_iat}

  defp check_jti(%{"jti" => jti}) when is_binary(jti) and jti != "" do
    if byte_size(jti) > @max_jti_length do
      {:error, :invalid_jti}
    else
      {:ok, jti}
    end
  end

  defp check_jti(%{"jti" => _}), do: {:error, :invalid_jti}
  defp check_jti(_claims), do: {:error, :missing_jti}

  # RFC 9449 §8: a server may require a server-issued nonce in the proof's
  # `nonce` claim. When the caller supplies a `:nonce_check`, the proof's
  # `nonce` (which may be nil if the client sent none) is handed to it; a
  # `{:error, :use_dpop_nonce}` tells the caller to answer with a fresh
  # nonce (HTTP 401 + `DPoP-Nonce`). With no `:nonce_check`, no nonce is
  # required. See `Attesto.DPoP.NonceStore`.
  defp check_nonce(claims, opts) do
    case Keyword.get(opts, :nonce_check) do
      nil ->
        :ok

      fun when is_function(fun, 1) ->
        case fun.(Map.get(claims, "nonce")) do
          :ok ->
            :ok

          {:error, :use_dpop_nonce} ->
            {:error, :use_dpop_nonce}

          other ->
            raise ArgumentError,
                  "Attesto.DPoP.verify_proof/2 :nonce_check must return :ok or " <>
                    "{:error, :use_dpop_nonce}; got #{inspect(other)}"
        end

      other ->
        raise ArgumentError,
              "Attesto.DPoP.verify_proof/2 :nonce_check must be a 1-arity function or nil; " <>
                "got #{inspect(other)}"
    end
  end

  defp check_replay(jti, opts) do
    case Keyword.get(opts, :replay_check) do
      nil ->
        :ok

      fun when is_function(fun, 2) ->
        case fun.(jti, replay_ttl(opts)) do
          :ok ->
            :ok

          {:error, :replay} ->
            # RFC 9449 §11.1: this proof was captured and replayed, or a
            # client is reusing identifiers it must not. See
            # `Attesto.Telemetry`.
            Attesto.Telemetry.dpop_replay_detected(jti)
            {:error, :replay}

          other ->
            raise ArgumentError,
                  "Attesto.DPoP.verify_proof/2 :replay_check must return :ok or " <>
                    "{:error, :replay}; got #{inspect(other)}"
        end

      other ->
        raise ArgumentError,
              "Attesto.DPoP.verify_proof/2 :replay_check must be a 2-arity function " <>
                "(jti, ttl_seconds) or nil; got #{inspect(other)}"
    end
  end

  # The replay store MUST remember a `jti` for at least as long as the
  # proof itself remains acceptable, or a captured proof could be replayed
  # after the cache forgot it but before its `iat` window closed. The
  # acceptance window is `max_age_seconds` plus the future-skew allowance,
  # so the cache TTL is derived from the verifier's own age policy rather
  # than a fixed default that could diverge from it.
  defp replay_ttl(opts) do
    Keyword.get(opts, :max_age_seconds, @default_max_age_seconds) + @future_skew_seconds
  end

  defp check_ath(claims, opts) do
    case {Keyword.get(opts, :access_token), Map.get(claims, "ath")} do
      {nil, ath} when is_binary(ath) or is_nil(ath) ->
        {:ok, ath}

      {token, ath} when is_binary(token) and is_binary(ath) ->
        if SecureCompare.equal?(ath, compute_ath(token)),
          do: {:ok, ath},
          else: {:error, :invalid_ath}

      {token, _ath} when is_binary(token) ->
        {:error, :missing_ath}

      {nil, _other} ->
        {:error, :invalid_ath}
    end
  end

  # ----- internal: helpers -----

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end

  defp require_string!(opts, key) do
    case Keyword.get(opts, key) do
      v when is_binary(v) and v != "" ->
        v

      other ->
        raise ArgumentError,
              "Attesto.DPoP.verify_proof/2 requires opt #{inspect(key)} as a non-empty " <>
                "string; got #{inspect(other)}"
    end
  end
end
