defmodule Attesto.Test.DPoP do
  @moduledoc """
  DPoP test fixtures for host application suites.

  A host that protects routes with Attesto's DPoP verification
  (`Attesto.DPoP.verify_proof/2` composed with `Attesto.Token.verify/3`)
  needs, in its own tests, the client half of the RFC 9449 exchange: a
  DPoP-sender-constrained access token, the matching proof JWT, and the
  deliberately-broken proofs that must be rejected. Hand-rolling those in
  every consumer re-implements JWS signing and the `cnf.jkt` / `ath`
  derivations the library already owns, and drifts from the verifier the
  moment a rule changes.

  This module ships under `lib/` (like `AttestoMCP.Test.DPoPReplay`) so a
  consumer can call it from its `test/` tree without depending on
  Attesto's own test support. It builds everything through the same
  primitives the production code uses - `Attesto.Token.mint/3`,
  `Attesto.DPoP.compute_jkt/1`, `Attesto.DPoP.compute_ath/1`, and
  `JOSE.JWS` - so a fixture is correct by construction against the
  verifier and stays in step with it.

  ## Proof key

  Every function takes the client's DPoP key as a `%JOSE.JWK{}` (generate
  one with `generate_key/1`, or supply your own EC/RSA/OKP key). The proof
  embeds only the key's **public** half in its protected header, as
  RFC 9449 §4.2 requires; `Attesto.DPoP.verify_proof/2` rejects any header
  carrying private-key material.

  ## Example

      jwk = Attesto.Test.DPoP.generate_key()

      {token, _resp} =
        Attesto.Test.DPoP.mint_access_token(config, %{
          kind: "client",
          sub: "oc_acme",
          scopes: ["read"],
          claims: %{"client_id" => "acme"}
        }, jwk)

      proof =
        Attesto.Test.DPoP.proof(jwk, "GET", "https://api.example/thing",
          access_token: token
        )

      {:ok, %{jkt: jkt}} =
        Attesto.DPoP.verify_proof(proof,
          http_method: "GET",
          http_uri: "https://api.example/thing",
          access_token: token
        )

      {:ok, _claims} = Attesto.Token.verify(config, token, dpop_jkt: jkt)
  """

  alias Attesto.Config
  alias Attesto.DPoP
  alias Attesto.Secret
  alias Attesto.SigningAlg
  alias Attesto.Token

  @proof_typ "dpop+jwt"
  @jti_byte_length 16

  @typedoc """
  A deliberate defect to bake into a proof so a negative test can assert
  the verifier rejects it:

    * `:wrong_htm` - sign a method the request will not carry.
    * `:wrong_htu` - sign a target URI the request will not carry.
    * `:missing_ath` - omit `ath` even though an access token is presented.
    * `:expired` - backdate `iat` past the acceptance window.
  """
  @type flaw :: :wrong_htm | :wrong_htu | :missing_ath | :expired

  @doc """
  Generate a fresh DPoP proof key.

  Defaults to an EC P-256 key (`ES256`), the smallest of the algorithms
  `Attesto.DPoP` accepts. Pass a `JOSE.JWK.generate_key/1` spec to choose
  another, e.g. `generate_key({:rsa, 2048})`.
  """
  @spec generate_key(term()) :: JOSE.JWK.t()
  def generate_key(spec \\ {:ec, "P-256"}) do
    JOSE.JWK.generate_key(spec)
  end

  @doc """
  Mint a DPoP-sender-constrained access token bound to `jwk`.

  Computes the RFC 7638 thumbprint of `jwk`'s public half and mints a
  token through `Attesto.Token.mint/3` with that thumbprint as the
  `cnf.jkt` binding (RFC 9449 §6 / RFC 7800). `principal` and `opts` are
  passed through to `mint/3` unchanged (except `:dpop_jkt`, which this
  function supplies), so the caller controls subject, scope, audience,
  lifetime, and clock exactly as with a direct mint.

  Returns `{access_token, token_response}` where `token_response` is the
  full `Attesto.Token.mint/3` map (`token_type` is `"DPoP"`). Raises if
  `mint/3` returns an error, since a fixture that fails to mint is a test
  bug, not a condition under test.
  """
  @spec mint_access_token(Config.t(), Token.principal(), JOSE.JWK.t(), Token.mint_opts()) ::
          {String.t(), Token.token_response()}
  def mint_access_token(%Config{} = config, principal, %JOSE.JWK{} = jwk, opts \\ []) do
    jkt = DPoP.compute_jkt(public_jwk(jwk))

    case Token.mint(config, principal, Keyword.put(opts, :dpop_jkt, jkt)) do
      {:ok, %{access_token: token} = response} ->
        {token, response}

      {:error, reason} ->
        raise ArgumentError,
              "Attesto.Test.DPoP.mint_access_token/4 could not mint a fixture token: " <>
                "#{inspect(reason)}"
    end
  end

  @doc """
  Build a valid DPoP proof JWT signed with `jwk` for `(htm, htu)`.

  The proof carries the protected header `%{"typ" => "dpop+jwt", "alg" =>
  ..., "jwk" => <public jwk>}` and the payload `%{"htm" => htm, "htu" =>
  htu, "iat" => now, "jti" => <random>}` (RFC 9449 §4.2). The signing
  `alg` defaults to the legacy identifier derived from the key via
  `Attesto.SigningAlg`, and only the key's public half is embedded, so the
  result verifies under `Attesto.DPoP.verify_proof/2`.

  Options:

    * `:access_token` - when given, the proof carries `ath`
      (`base64url(SHA-256(access_token))`, RFC 9449 §4.3) so it verifies
      against the bound token on a protected-resource request. Omit it for
      a token-endpoint proof, where no access token exists yet.
    * `:nonce` - a server-issued DPoP nonce to carry in the `nonce` claim
      (RFC 9449 §8).
    * `:now` - `DateTime` or unix-seconds clock used for `iat`. Defaults
      to `DateTime.utc_now/0`.
    * `:jti` - override the random replay identifier (e.g. to drive a
      replay test that presents the same `jti` twice).
    * `:alg` - override the inferred identifier with any key-compatible
      algorithm accepted by `Attesto.DPoP.allowed_algs/0`, including RFC 9864
      `Ed25519` or `Ed448` when the configured JOSE backend supports it.
  """
  @spec proof(JOSE.JWK.t(), String.t(), String.t(), keyword()) :: String.t()
  def proof(%JOSE.JWK{} = jwk, htm, htu, opts \\ []) when is_binary(htm) and is_binary(htu) and is_list(opts) do
    sign(jwk, payload(htm, htu, opts), opts)
  end

  @doc """
  Build a DPoP proof carrying a single deliberate defect, for negative
  tests that assert `Attesto.DPoP.verify_proof/2` rejects it.

  `flaw` is one of the `t:flaw/0` values. `htm`/`htu` are the values the
  request will actually carry; the defect is applied relative to them
  (e.g. `:wrong_htu` signs a different URI than `htu`). `opts` is the same
  as `proof/4`; for `:missing_ath`, pass `:access_token` (the proof omits
  `ath` despite the token being presented, which the verifier rejects with
  `:missing_ath`).
  """
  @spec invalid_proof(JOSE.JWK.t(), flaw(), String.t(), String.t(), keyword()) :: String.t()
  def invalid_proof(%JOSE.JWK{} = jwk, flaw, htm, htu, opts \\ [])
      when is_binary(htm) and is_binary(htu) and is_list(opts) do
    sign(jwk, flawed_payload(flaw, htm, htu, opts), opts)
  end

  # ----- internal: payloads -----

  defp payload(htm, htu, opts) do
    %{
      "htm" => htm,
      "htu" => htu,
      "iat" => unix_now(opts),
      "jti" => Keyword.get_lazy(opts, :jti, &generate_jti/0)
    }
    |> maybe_put_ath(Keyword.get(opts, :access_token))
    |> maybe_put_nonce(Keyword.get(opts, :nonce))
  end

  # A method the request will not carry: `verify_proof/2` fails `:invalid_htm`.
  defp flawed_payload(:wrong_htm, htm, htu, opts) do
    payload(other_method(htm), htu, opts)
  end

  # A target URI the request will not carry: fails `:invalid_htu`.
  defp flawed_payload(:wrong_htu, htm, htu, opts) do
    payload(htm, other_uri(htu), opts)
  end

  # No `ath` even though an access token is presented: fails `:missing_ath`.
  defp flawed_payload(:missing_ath, htm, htu, opts) do
    htm
    |> payload(htu, Keyword.delete(opts, :access_token))
    |> maybe_put_nonce(Keyword.get(opts, :nonce))
  end

  # `iat` backdated past the acceptance window: fails `:proof_expired`. The
  # verifier's window is `max_age_seconds` (default 60) plus a small future
  # skew, so 600 seconds is comfortably stale.
  defp flawed_payload(:expired, htm, htu, opts) do
    stale_now = unix_now(opts) - 600
    payload(htm, htu, Keyword.put(opts, :now, stale_now))
  end

  defp maybe_put_ath(payload, nil), do: payload
  defp maybe_put_ath(payload, token) when is_binary(token), do: Map.put(payload, "ath", DPoP.compute_ath(token))

  defp maybe_put_nonce(payload, nil), do: payload
  defp maybe_put_nonce(payload, nonce) when is_binary(nonce), do: Map.put(payload, "nonce", nonce)

  # A distinct, still-valid HTTP method so the only thing wrong with a
  # `:wrong_htm` proof is the method mismatch.
  defp other_method("POST"), do: "GET"
  defp other_method(_htm), do: "POST"

  # A distinct, still-HTTPS, query/fragment-free URI so the only thing
  # wrong with a `:wrong_htu` proof is the target mismatch.
  defp other_uri(htu) do
    if htu == "https://attesto.test/other", do: "https://attesto.test/another", else: "https://attesto.test/other"
  end

  # ----- internal: signing -----

  # Mirror `Attesto.Token.sign/2`: sign through `JOSE.JWS` (not
  # `JOSE.JWT`) so the protected header is emitted verbatim and the
  # `typ: "dpop+jwt"` survives, then compact. Only the public half of the
  # key is embedded in `jwk`, as RFC 9449 §4.2 requires.
  defp sign(jwk, payload, opts) do
    pub = public_jwk(jwk)
    alg = Keyword.get(opts, :alg, SigningAlg.infer(jwk))
    alg = validate_dpop_alg!(alg, jwk)
    header = %{"typ" => @proof_typ, "alg" => alg, "jwk" => public_jwk_map(pub)}
    signed = JOSE.JWS.sign(jwk, JSON.encode!(payload), header)
    {_protected, compact} = JOSE.JWS.compact(signed)
    compact
  end

  defp public_jwk(jwk), do: JOSE.JWK.to_public(jwk)

  defp validate_dpop_alg!(alg, jwk) when is_binary(alg) do
    if alg not in DPoP.allowed_algs() do
      raise ArgumentError, "unsupported DPoP signing algorithm #{inspect(alg)} for the configured JOSE backend"
    end

    {_modules, fields} = JOSE.JWK.to_public_map(jwk)

    case {alg, fields} do
      {rsa_alg, %{"kty" => "RSA"}} when rsa_alg in ~w(RS256 RS384 RS512 PS256 PS384 PS512) -> alg
      _ -> SigningAlg.validate_for_key!(alg, jwk)
    end
  end

  defp public_jwk_map(pub) do
    {_modules, map} = JOSE.JWK.to_map(pub)
    map
  end

  defp generate_jti do
    Secret.generate(@jti_byte_length)
  end

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end
end
