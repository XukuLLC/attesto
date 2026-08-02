defmodule Attesto.DPoPCorpusTest do
  @moduledoc """
  A consolidated DPoP proof corpus: a fixed set of representative valid
  and invalid proof vectors run through `Attesto.DPoP.verify_proof/2` in
  one place.

  The four sibling suites (`dpop_test.exs`, `dpop_header_test.exs`,
  `dpop_htu_test.exs`, `dpop_nonce_test.exs`) each cover one axis in depth.
  This file is the cross-cutting smoke corpus: it asserts that EVERY
  `verify_error` atom documented in `Attesto.DPoP`'s typespec
  (`:invalid_proof`, `:invalid_signature`, `:invalid_typ`, `:invalid_alg`,
  `:unsupported_critical_header`, `:missing_jwk`, `:invalid_jwk`,
  `:invalid_htm`, `:invalid_htu`, `:missing_jti`, `:invalid_jti`,
  `:missing_ath`, `:invalid_ath`, `:missing_iat`, `:invalid_iat`,
  `:proof_expired`, `:replay`, `:use_dpop_nonce`) is reachable, and that
  the happy paths across the algorithm whitelist all succeed.

  The corpus deliberately includes a handful of cases the per-axis suites
  do not exercise:

    * timestamp-window BOUNDARIES verified against a pinned clock: `iat`
      at exactly `now - max_age_seconds` (the oldest still-acceptable
      moment) and at exactly `now + future_skew` (the furthest-future
      still-acceptable moment), plus the one-second-past-boundary failures
      on each side;
    * `jti` at exactly the 256-byte cap (accepted) and one byte over
      (rejected), checked here as part of the unified corpus rather than
      only in `dpop_test.exs`;
    * the `:replay` and `:use_dpop_nonce` FAILURE paths, including a
      `:replay_check` that fires AFTER every other gate has passed (no
      earlier verifier failure masks it);
    * non-ASCII UTF-8 in claim values - a Cyrillic `jti`, an emoji
      `nonce` - which the ASCII-only sibling suites never feed the
      verifier.

  Every assertion drives the pure function `verify_proof/2` with no
  keystore and no application env, so the module is `async: true`. The
  pinned-clock cases reuse a single reference instant so a slow run can
  never drift a proof out of its `iat` window mid-assertion.
  """
  use ExUnit.Case, async: true

  alias Attesto.DPoP
  alias Attesto.Test.Factory

  @http_method "POST"
  @http_uri "https://api.example.com/oauth/token"

  # The whole corpus is verified against this one frozen instant so the
  # boundary cases (iat == now - max_age, iat == now + skew) are exact and
  # reproducible regardless of wall-clock drift during the run.
  @now 1_700_000_000

  # Mirrors Attesto.DPoP's own constants (kept literal here, not imported,
  # so a silent change to the module's policy surfaces as a corpus failure
  # rather than tracking along with it).
  @default_max_age 60
  @future_skew 60

  # -----------------------------------------------------------------
  # proof-construction helpers (mirroring dpop_header_test.exs /
  # dpop_nonce_test.exs: forge the protected header by hand when JOSE
  # would refuse to emit the shape we want to test)
  # -----------------------------------------------------------------

  defp gen_ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})
  defp gen_rsa_key, do: JOSE.JWK.generate_key({:rsa, 2048})
  defp gen_eddsa_key, do: JOSE.JWK.generate_key({:okp, :Ed25519})

  defp public_map(%JOSE.JWK{} = key) do
    {_, map} = JOSE.JWK.to_public_map(key)
    map
  end

  defp base_header(jwk_map, overrides \\ %{}) do
    Map.merge(%{"typ" => "dpop+jwt", "alg" => "ES256", "jwk" => jwk_map}, overrides)
  end

  defp base_claims(overrides \\ %{}) do
    Map.merge(
      %{
        "htm" => @http_method,
        "htu" => @http_uri,
        "iat" => @now,
        "jti" => "jti-" <> Integer.to_string(System.unique_integer([:positive]))
      },
      overrides
    )
  end

  # Sign a proof normally: JOSE derives the wire `alg` from `header["alg"]`,
  # so the signature is genuinely consistent with the declared alg.
  defp sign(key, header, claims) do
    {_protected, compact} =
      key
      |> JOSE.JWT.sign(header, claims)
      |> JOSE.JWS.compact()

    compact
  end

  defp encode_segment(map) do
    map |> JSON.encode!() |> Base.url_encode64(padding: false)
  end

  # Replace the protected header of a real compact JWS while reusing its
  # signature segment. Used for the cases JOSE.JWT.sign would not emit (a
  # spliced-in bad `alg`, a removed `jwk`, a non-list `crit`). The point of
  # such a vector is always WHICH guard fires first, so the now-mismatched
  # signature on the swapped header is intentional.
  defp reheader(signed_compact, new_header_map) do
    [_old, payload, sig] = String.split(signed_compact, ".")
    Enum.join([encode_segment(new_header_map), payload, sig], ".")
  end

  # Verify opts pinned to the corpus clock; callers add the case-specific
  # extras (access_token, replay_check, nonce_check, max_age_seconds, …).
  defp opts(extra \\ []) do
    Keyword.merge([http_method: @http_method, http_uri: @http_uri, now: @now], extra)
  end

  # =================================================================
  # VALID CORPUS - one vector per accepted algorithm, plus the
  # ath-bound and Factory-built happy paths.
  # =================================================================

  describe "valid corpus" do
    test "valid ES256 proof verifies and returns the embedded key's thumbprint" do
      key = gen_ec_key()
      claims = base_claims()
      proof = sign(key, base_header(public_map(key)), claims)

      assert {:ok, result} = DPoP.verify_proof(proof, opts())
      assert result.jkt == JOSE.JWK.thumbprint(key)
      assert result.jti == claims["jti"]
      assert result.iat == @now
      assert result.htm == @http_method
      assert result.htu == @http_uri
      assert result.ath == nil
    end

    test "valid RS256 proof verifies" do
      key = gen_rsa_key()
      proof = sign(key, base_header(public_map(key), %{"alg" => "RS256"}), base_claims())

      assert {:ok, %{jkt: jkt}} = DPoP.verify_proof(proof, opts())
      assert jkt == JOSE.JWK.thumbprint(key)
    end

    test "valid PS256 proof verifies" do
      key = gen_rsa_key()
      proof = sign(key, base_header(public_map(key), %{"alg" => "PS256"}), base_claims())

      assert {:ok, %{jkt: jkt}} = DPoP.verify_proof(proof, opts())
      assert jkt == JOSE.JWK.thumbprint(key)
    end

    test "valid EdDSA proof verifies" do
      key = gen_eddsa_key()
      proof = sign(key, base_header(public_map(key), %{"alg" => "EdDSA"}), base_claims())

      assert {:ok, %{jkt: jkt}} = DPoP.verify_proof(proof, opts())
      assert jkt == JOSE.JWK.thumbprint(key)
    end

    test "valid ath-bound proof verifies when :access_token matches the ath claim" do
      access_token = "atk_" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
      ath = DPoP.compute_ath(access_token)
      {proof, _jkt} = Factory.dpop_proof(ath: ath, iat: @now)

      assert {:ok, %{ath: ^ath}} =
               DPoP.verify_proof(proof, opts(access_token: access_token))
    end

    test "valid Factory proof (the default end-to-end vector) verifies" do
      {proof, jkt} = Factory.dpop_proof(iat: @now)

      assert {:ok, %{jkt: ^jkt, ath: nil}} = DPoP.verify_proof(proof, opts())
    end
  end

  # =================================================================
  # INVALID CORPUS - one descriptively-named vector per verify_error
  # atom. Each is the cleanest path that makes exactly that guard fire.
  # =================================================================

  describe "invalid corpus: structural / header errors" do
    test "rejects :invalid_proof when the input is not a 3-segment JWS" do
      for bad <- ["", "not-a-jwt", "only.two", "a.b.c.d", "!!!.@@@.###"] do
        assert {:error, :invalid_proof} = DPoP.verify_proof(bad, opts()),
               "expected :invalid_proof for #{inspect(bad)}"
      end
    end

    test "rejects :invalid_proof when the input is not even a binary" do
      for bad <- [nil, 42, %{}, :atom, [~c"a"]] do
        assert {:error, :invalid_proof} = DPoP.verify_proof(bad, opts()),
               "expected :invalid_proof for #{inspect(bad)}"
      end
    end

    test "rejects :invalid_typ when typ != dpop+jwt" do
      key = gen_ec_key()
      proof = sign(key, base_header(public_map(key), %{"typ" => "JWT"}), base_claims())

      assert {:error, :invalid_typ} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_alg when alg=HS256 (symmetric, not whitelisted)" do
      # The attacker pattern: a symmetric secret signs, but the header still
      # ships a plausible-looking public jwk. The alg whitelist refuses HS256
      # before the JWK is consulted.
      secret = JOSE.JWK.from_oct(:crypto.strong_rand_bytes(32))
      decoy_pub = public_map(gen_ec_key())
      proof = sign(secret, %{"typ" => "dpop+jwt", "alg" => "HS256", "jwk" => decoy_pub}, base_claims())

      assert {:error, :invalid_alg} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_alg when alg=none (unsecured JWS)" do
      key = gen_ec_key()

      header_b64 =
        encode_segment(%{"alg" => "none", "jwk" => public_map(key), "typ" => "dpop+jwt"})

      payload_b64 = encode_segment(base_claims())
      # An alg=none unsecured JWS has the literal compact form `h.p.`.
      proof = header_b64 <> "." <> payload_b64 <> "."

      assert {:error, :invalid_alg} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :unsupported_critical_header when the header carries crit" do
      key = gen_ec_key()
      proof = sign(key, base_header(public_map(key), %{"crit" => ["b64"], "b64" => false}), base_claims())

      assert {:error, :unsupported_critical_header} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :missing_jwk when the header has no embedded jwk" do
      key = gen_ec_key()
      signed = sign(key, base_header(public_map(key)), base_claims())
      forged = reheader(signed, %{"typ" => "dpop+jwt", "alg" => "ES256"})

      assert {:error, :missing_jwk} = DPoP.verify_proof(forged, opts())
    end

    test "rejects :invalid_jwk when the embedded jwk smuggles private-key material (d)" do
      key = gen_ec_key()
      {_, priv_map} = JOSE.JWK.to_map(key)
      assert Map.has_key?(priv_map, "d")
      proof = sign(key, base_header(priv_map), base_claims())

      assert {:error, :invalid_jwk} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_signature when the proof is signed by a key other than the embedded jwk" do
      signer = gen_ec_key()
      embedded = gen_ec_key()
      proof = sign(signer, base_header(public_map(embedded)), base_claims())

      assert {:error, :invalid_signature} = DPoP.verify_proof(proof, opts())
    end
  end

  describe "invalid corpus: claim errors" do
    test "rejects :invalid_htm when the htm claim mismatches the request method" do
      {proof, _jkt} = Factory.dpop_proof(htm: "GET", iat: @now)

      assert {:error, :invalid_htm} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_htu when the htu claim mismatches the request uri" do
      {proof, _jkt} = Factory.dpop_proof(htu: "https://evil.example/oauth/token", iat: @now)

      assert {:error, :invalid_htu} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :missing_iat when the iat claim is absent" do
      key = gen_ec_key()
      claims = %{"htm" => @http_method, "htu" => @http_uri, "jti" => "j1"}
      proof = sign(key, base_header(public_map(key)), claims)

      assert {:error, :missing_iat} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_iat when the iat claim is not an integer" do
      key = gen_ec_key()
      proof = sign(key, base_header(public_map(key)), base_claims(%{"iat" => "soon"}))

      assert {:error, :invalid_iat} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :missing_jti when the jti claim is absent" do
      key = gen_ec_key()
      claims = %{"htm" => @http_method, "htu" => @http_uri, "iat" => @now}
      proof = sign(key, base_header(public_map(key)), claims)

      assert {:error, :missing_jti} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_jti when the jti claim is an empty string" do
      key = gen_ec_key()
      proof = sign(key, base_header(public_map(key)), base_claims(%{"jti" => ""}))

      assert {:error, :invalid_jti} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :missing_ath when :access_token is set but the proof carries no ath" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now)

      assert {:error, :missing_ath} = DPoP.verify_proof(proof, opts(access_token: "atk_xyz"))
    end

    test "rejects :invalid_ath when the ath claim hashes a different token" do
      {proof, _jkt} = Factory.dpop_proof(ath: DPoP.compute_ath("atk_other"), iat: @now)

      assert {:error, :invalid_ath} = DPoP.verify_proof(proof, opts(access_token: "atk_real"))
    end
  end

  # =================================================================
  # TIMESTAMP WINDOW BOUNDARIES - exact-edge vectors verified against
  # the pinned @now. The acceptance window is
  # [now - max_age, now + future_skew] inclusive.
  # =================================================================

  describe "iat window boundaries (pinned clock)" do
    test "accepts iat at exactly now - max_age_seconds (oldest acceptable)" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now - @default_max_age)

      assert {:ok, _} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :proof_expired at one second past now - max_age_seconds" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now - @default_max_age - 1)

      assert {:error, :proof_expired} = DPoP.verify_proof(proof, opts())
    end

    test "accepts iat at exactly now + future_skew (furthest-future acceptable)" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now + @future_skew)

      assert {:ok, _} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_iat at one second past now + future_skew" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now + @future_skew + 1)

      assert {:error, :invalid_iat} = DPoP.verify_proof(proof, opts())
    end

    test "a custom :max_age_seconds moves the lower boundary exactly" do
      # iat is 200s old: rejected under the default 60s window, accepted at
      # the exact edge of a 200s window, rejected one second past it.
      stale = @now - 200
      {proof, _jkt} = Factory.dpop_proof(iat: stale)

      assert {:error, :proof_expired} = DPoP.verify_proof(proof, opts())
      assert {:ok, _} = DPoP.verify_proof(proof, opts(max_age_seconds: 200))
      assert {:error, :proof_expired} = DPoP.verify_proof(proof, opts(max_age_seconds: 199))
    end
  end

  # =================================================================
  # JTI LENGTH BOUNDARY - the 256-byte memory-exhaustion cap.
  # =================================================================

  describe "jti length boundary" do
    test "accepts a jti at exactly the 256-byte cap" do
      jti = String.duplicate("a", 256)
      {proof, _jkt} = Factory.dpop_proof(jti: jti, iat: @now)

      assert {:ok, %{jti: ^jti}} = DPoP.verify_proof(proof, opts())
    end

    test "rejects :invalid_jti at one byte over the 256-byte cap" do
      oversized = String.duplicate("a", 257)
      {proof, _jkt} = Factory.dpop_proof(jti: oversized, iat: @now)

      assert {:error, :invalid_jti} = DPoP.verify_proof(proof, opts())
    end

    test "the cap is on BYTES, not characters: a 256-codepoint multibyte jti is over the cap" do
      # "ä" is 2 UTF-8 bytes; 256 of them is 512 bytes, past the 256-byte cap.
      jti = String.duplicate("ä", 256)
      assert byte_size(jti) == 512
      {proof, _jkt} = Factory.dpop_proof(jti: jti, iat: @now)

      assert {:error, :invalid_jti} = DPoP.verify_proof(proof, opts())
    end
  end

  # =================================================================
  # REPLAY GATE - both directions. The :replay_check runs LAST, after
  # every other gate, so its failure is not masked by an earlier one.
  # =================================================================

  describe "replay gate (:replay_check)" do
    test "rejects :replay when the check reports the jti has been seen" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now)
      replay_check = fn _jti, _ttl -> {:error, :replay} end

      assert {:error, :replay} = DPoP.verify_proof(proof, opts(replay_check: replay_check))
    end

    test ":replay fires only after every other gate passes (clean proof reaches it)" do
      # This is the case the sibling suites under-cover: a fully valid proof
      # that fails ONLY at the replay gate, with the check observing the
      # namespaced replay key (jkt:jti) and the acceptance-window ttl plus 1s
      # retention margin (default max_age 60 + skew 60 + 1 = 121).
      jti = "corpus-replay-#{System.unique_integer([:positive])}"
      {proof, jkt} = Factory.dpop_proof(jti: jti, iat: @now)
      replay_key = jkt <> ":" <> jti
      parent = self()

      replay_check = fn seen, ttl ->
        send(parent, {:replay_seen, seen, ttl})
        {:error, :replay}
      end

      assert {:error, :replay} = DPoP.verify_proof(proof, opts(replay_check: replay_check))
      assert_received {:replay_seen, ^replay_key, 121}
    end

    test ":replay_check is NOT consulted when an earlier gate (htm) already fails" do
      parent = self()
      replay_check = fn jti, _ttl -> send(parent, {:should_not_run, jti}) end
      {proof, _jkt} = Factory.dpop_proof(htm: "DELETE", iat: @now)

      assert {:error, :invalid_htm} = DPoP.verify_proof(proof, opts(replay_check: replay_check))
      refute_received {:should_not_run, _}
    end

    test "a clean proof passes the replay gate when the check reports :ok" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now)
      replay_check = fn _jti, _ttl -> :ok end

      assert {:ok, _} = DPoP.verify_proof(proof, opts(replay_check: replay_check))
    end
  end

  # =================================================================
  # NONCE GATE - the RFC 9449 §8 :use_dpop_nonce challenge path.
  # =================================================================

  describe "nonce gate (:nonce_check)" do
    test "rejects :use_dpop_nonce when the proof carries no nonce but one is required" do
      {proof, _jkt} = Factory.dpop_proof(iat: @now)

      nonce_check = fn
        nonce when is_binary(nonce) -> :ok
        _ -> {:error, :use_dpop_nonce}
      end

      assert {:error, :use_dpop_nonce} = DPoP.verify_proof(proof, opts(nonce_check: nonce_check))
    end

    test "rejects :use_dpop_nonce when the proof's nonce is stale/unrecognized" do
      key = gen_ec_key()
      proof = sign(key, base_header(public_map(key)), base_claims(%{"nonce" => "stale"}))

      nonce_check = fn
        "currently-live" -> :ok
        _ -> {:error, :use_dpop_nonce}
      end

      assert {:error, :use_dpop_nonce} = DPoP.verify_proof(proof, opts(nonce_check: nonce_check))
    end

    test "a proof echoing the accepted nonce passes the gate" do
      key = gen_ec_key()
      proof = sign(key, base_header(public_map(key)), base_claims(%{"nonce" => "good-nonce"}))

      nonce_check = fn
        "good-nonce" -> :ok
        _ -> {:error, :use_dpop_nonce}
      end

      assert {:ok, _} = DPoP.verify_proof(proof, opts(nonce_check: nonce_check))
    end
  end

  # =================================================================
  # NON-ASCII / UTF-8 CLAIM VALUES - the ASCII-only sibling suites
  # never feed these to the verifier. Claim values are opaque strings
  # to the verifier; only their byte length (jti) and exact equality
  # (nonce) matter, and UTF-8 must not break either.
  # =================================================================

  describe "non-ASCII utf-8 claim values" do
    test "a Cyrillic jti round-trips: it is returned verbatim and counted by bytes" do
      # "тест" is 4 Cyrillic codepoints, 8 UTF-8 bytes - well under the cap.
      jti = "тест-#{System.unique_integer([:positive])}"
      {proof, _jkt} = Factory.dpop_proof(jti: jti, iat: @now)

      assert {:ok, %{jti: ^jti}} = DPoP.verify_proof(proof, opts())
    end

    test "an emoji nonce is compared by exact UTF-8 equality" do
      key = gen_ec_key()
      nonce = "nonce-🔐-✓"
      proof = sign(key, base_header(public_map(key)), base_claims(%{"nonce" => nonce}))
      parent = self()

      nonce_check = fn seen ->
        send(parent, {:nonce_seen, seen})
        if seen == nonce, do: :ok, else: {:error, :use_dpop_nonce}
      end

      assert {:ok, _} = DPoP.verify_proof(proof, opts(nonce_check: nonce_check))
      # The verifier handed the check the exact multibyte value, byte-for-byte.
      assert_received {:nonce_seen, ^nonce}
    end

    test "a Cyrillic jti just over the byte cap is rejected (byte counting, not codepoints)" do
      # 86 two-byte codepoints + a 4-byte prefix counts in bytes: build a
      # value whose byte_size is 257 to land exactly one byte over the cap.
      jti = String.duplicate("я", 128) <> "a"
      assert byte_size(jti) == 257
      {proof, _jkt} = Factory.dpop_proof(jti: jti, iat: @now)

      assert {:error, :invalid_jti} = DPoP.verify_proof(proof, opts())
    end

    test "an emoji jti under the byte cap round-trips verbatim" do
      jti = "🔑-#{System.unique_integer([:positive])}"
      {proof, _jkt} = Factory.dpop_proof(jti: jti, iat: @now)

      assert {:ok, %{jti: ^jti}} = DPoP.verify_proof(proof, opts())
    end
  end
end
