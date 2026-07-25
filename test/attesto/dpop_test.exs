defmodule Attesto.DPoPTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.DPoP
  alias Attesto.Test.Factory

  @http_method "POST"
  @http_uri "https://api.example.com/oauth/token"

  # -----------------------------------------------------------------
  # helpers
  # -----------------------------------------------------------------

  defp gen_ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})
  defp gen_rsa_key(bits \\ 2048), do: JOSE.JWK.generate_key({:rsa, bits})

  defp public_map(%JOSE.JWK{} = key) do
    {_, map} = JOSE.JWK.to_public_map(key)
    map
  end

  defp unix_now, do: System.system_time(:second)

  defp build_claims(overrides \\ %{}) do
    Map.merge(
      %{
        "htm" => @http_method,
        "htu" => @http_uri,
        "iat" => unix_now(),
        "jti" => "jti-" <> Integer.to_string(System.unique_integer([:positive]))
      },
      overrides
    )
  end

  defp build_header(jwk_map, overrides \\ %{}) do
    Map.merge(
      %{"alg" => "ES256", "jwk" => jwk_map, "typ" => "dpop+jwt"},
      overrides
    )
  end

  defp sign_proof(key, header, claims) do
    signed = JOSE.JWT.sign(key, header, claims)
    {_protected, compact} = JOSE.JWS.compact(signed)
    compact
  end

  # Compact-form DPoP proof signed by a freshly-generated key. The header
  # carries the public half of `key`; the claims carry htm/htu/iat/jti.
  # Overrides may replace any of those.
  defp valid_proof(opts \\ []) do
    key = Keyword.get(opts, :key, gen_ec_key())
    pub_map = public_map(key)
    header = build_header(pub_map, Keyword.get(opts, :header_overrides, %{}))
    claims = build_claims(Keyword.get(opts, :claim_overrides, %{}))
    proof = sign_proof(key, header, claims)
    {proof, key, claims, header}
  end

  defp base_opts(extra \\ []) do
    Keyword.merge([http_method: @http_method, http_uri: @http_uri], extra)
  end

  # -----------------------------------------------------------------
  # happy path
  # -----------------------------------------------------------------

  describe "verify_proof/2 happy path" do
    test "verifies a Factory proof and returns jkt/jti/iat/htm/htu/ath" do
      {proof, jkt} = Factory.dpop_proof()

      assert {:ok, result} = DPoP.verify_proof(proof, base_opts())
      assert result.jkt == jkt
      assert is_binary(result.jti)
      assert is_integer(result.iat)
      assert result.htm == @http_method
      assert result.htu == @http_uri
      assert result.ath == nil
    end

    test "verifies a well-formed ES256 proof and returns the embedded key thumbprint" do
      {proof, key, claims, _header} = valid_proof()

      assert {:ok, %{ath: nil, jkt: jkt, jti: jti} = result} =
               DPoP.verify_proof(proof, base_opts())

      assert jkt == JOSE.JWK.thumbprint(key)
      assert jti == claims["jti"]
      assert result.htm == @http_method
      assert result.htu == @http_uri
      assert result.iat == claims["iat"]
    end

    test "verifies an RS256 proof" do
      key = gen_rsa_key()
      header = build_header(public_map(key), %{"alg" => "RS256"})
      claims = build_claims()
      proof = sign_proof(key, header, claims)

      assert {:ok, %{jkt: jkt}} = DPoP.verify_proof(proof, base_opts())
      assert jkt == JOSE.JWK.thumbprint(key)
    end

    test "verifies a PS256 proof" do
      key = gen_rsa_key()
      header = build_header(public_map(key), %{"alg" => "PS256"})
      claims = build_claims()
      proof = sign_proof(key, header, claims)

      assert {:ok, %{jkt: jkt}} = DPoP.verify_proof(proof, base_opts())
      assert jkt == JOSE.JWK.thumbprint(key)
    end

    test "rejects RSA proof keys with moduli below 2048 bits" do
      key = gen_rsa_key(1024)

      for alg <- ~w(RS256 RS384 RS512 PS256 PS384 PS512) do
        header = build_header(public_map(key), %{"alg" => alg})
        proof = sign_proof(key, header, build_claims())

        assert {:error, :invalid_jwk} = DPoP.verify_proof(proof, base_opts()),
               "expected 1024-bit #{alg} proof key to be rejected"
      end
    end

    test "verifies RFC 9864 Ed25519 and Ed448 proofs" do
      ed25519 = JOSE.JWK.generate_key({:okp, :Ed25519})
      ed25519_proof = sign_proof(ed25519, build_header(public_map(ed25519), %{"alg" => "Ed25519"}), build_claims())
      assert {:ok, _result} = DPoP.verify_proof(ed25519_proof, base_opts())

      enable_ed448_support()
      ed448 = JOSE.JWK.generate_key({:okp, :Ed448})
      ed448_proof = sign_proof(ed448, build_header(public_map(ed448), %{"alg" => "Ed448"}), build_claims())
      assert {:ok, _result} = DPoP.verify_proof(ed448_proof, base_opts())
    end

    test "rejects an explicit Edwards identifier that does not match the embedded curve" do
      enable_ed448_support()
      key = JOSE.JWK.generate_key({:okp, :Ed448})
      proof = sign_proof(key, build_header(public_map(key), %{"alg" => "Ed448"}), build_claims())
      [_header, payload, signature] = String.split(proof, ".")

      mismatched_header =
        key
        |> public_map()
        |> build_header(%{"alg" => "Ed25519"})
        |> JSON.encode!()
        |> Base.url_encode64(padding: false)

      assert {:error, :invalid_jwk} =
               DPoP.verify_proof(Enum.join([mismatched_header, payload, signature], "."), base_opts())
    end

    test "ath is verified when :access_token is provided" do
      access_token = "atk_" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
      ath = DPoP.compute_ath(access_token)

      {proof, _jkt} = Factory.dpop_proof(ath: ath)

      assert {:ok, %{ath: ^ath}} =
               DPoP.verify_proof(proof, base_opts(access_token: access_token))
    end

    test "a clean proof htu matches a live uri carrying a query and fragment" do
      claim_uri = "https://api.example.com/positions"
      live_uri = "https://api.example.com/positions?cursor=abc#frag"

      {proof, _jkt} = Factory.dpop_proof(htu: claim_uri)
      assert {:ok, _} = DPoP.verify_proof(proof, base_opts(http_uri: live_uri))
    end

    test "a proof whose own htu carries a query still matches the effective target uri" do
      {proof, _jkt} = Factory.dpop_proof(htu: "https://api.example.com/positions?cursor=xyz")

      assert {:ok, _} =
               DPoP.verify_proof(proof, base_opts(http_uri: "https://api.example.com/positions"))
    end

    test "honors :now opt as a DateTime" do
      iat = 1_700_000_000
      {proof, _jkt} = Factory.dpop_proof(iat: iat)

      assert {:ok, _} =
               DPoP.verify_proof(proof, base_opts(now: DateTime.from_unix!(iat + 30, :second)))
    end

    test "honors :now opt as a unix integer" do
      iat = 1_700_000_000
      {proof, _jkt} = Factory.dpop_proof(iat: iat)

      assert {:ok, _} = DPoP.verify_proof(proof, base_opts(now: iat + 30))
    end
  end

  # -----------------------------------------------------------------
  # header validation: typ
  # -----------------------------------------------------------------

  describe "verify_proof/2 typ validation" do
    test "rejects proof with typ != dpop+jwt" do
      key = gen_ec_key()
      header = build_header(public_map(key), %{"typ" => "JWT"})
      proof = sign_proof(key, header, build_claims())

      assert {:error, :invalid_typ} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects proof missing typ" do
      key = gen_ec_key()
      header = %{"alg" => "ES256", "jwk" => public_map(key)}
      proof = sign_proof(key, header, build_claims())

      assert {:error, :invalid_typ} = DPoP.verify_proof(proof, base_opts())
    end
  end

  # -----------------------------------------------------------------
  # header validation: alg whitelist
  # -----------------------------------------------------------------

  describe "verify_proof/2 alg validation" do
    test "rejects symmetric algorithms (HS256, HS384, HS512)" do
      # Forge an HS-signed proof manually. The header still claims to
      # carry a public JWK; that is exactly the attacker pattern (downgrade
      # alg, ride along with a plausible-looking jwk).
      for hs <- ~w(HS256 HS384 HS512) do
        secret_jwk = JOSE.JWK.from_oct(:crypto.strong_rand_bytes(32))
        decoy_pub = public_map(gen_ec_key())
        header = %{"alg" => hs, "jwk" => decoy_pub, "typ" => "dpop+jwt"}
        signed = JOSE.JWT.sign(secret_jwk, header, build_claims())
        {_, proof} = JOSE.JWS.compact(signed)

        assert {:error, :invalid_alg} = DPoP.verify_proof(proof, base_opts()),
               "expected :invalid_alg for alg=#{hs}"
      end
    end

    test "rejects the unsecured alg=none" do
      key = gen_ec_key()
      claims = build_claims()

      header_b64 =
        %{"alg" => "none", "jwk" => public_map(key), "typ" => "dpop+jwt"}
        |> JSON.encode!()
        |> Base.url_encode64(padding: false)

      payload_b64 = claims |> JSON.encode!() |> Base.url_encode64(padding: false)
      proof = header_b64 <> "." <> payload_b64 <> "."

      assert {:error, :invalid_alg} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects an unknown alg outright" do
      key = gen_ec_key()
      header = build_header(public_map(key), %{"alg" => "RS999"})
      # Use a recognized alg to actually sign, then splice the bad alg into
      # the protected header so the structure is otherwise well-formed.
      proof = sign_proof(key, build_header(public_map(key)), build_claims())

      [_, payload, sig] = String.split(proof, ".")
      bad_header_b64 = header |> JSON.encode!() |> Base.url_encode64(padding: false)
      forged = Enum.join([bad_header_b64, payload, sig], ".")

      assert {:error, :invalid_alg} = DPoP.verify_proof(forged, base_opts())
    end

    test "allowed_algs/0 is an asymmetric whitelist (no HS*, no none)" do
      algs = DPoP.allowed_algs()

      refute "none" in algs
      refute Enum.any?(algs, &String.starts_with?(&1, "HS"))
      assert "ES256" in algs
      assert "RS256" in algs
      assert "PS256" in algs
      assert "EdDSA" in algs
      assert "Ed25519" in algs

      {:alg, jose_jws_algs} = Keyword.fetch!(JOSE.JWA.supports(), :jws)
      assert "Ed448" in algs == "Ed448" in jose_jws_algs
    end
  end

  # -----------------------------------------------------------------
  # header validation: jwk
  # -----------------------------------------------------------------

  describe "verify_proof/2 jwk validation" do
    test "rejects proof missing the embedded jwk" do
      key = gen_ec_key()
      header = %{"alg" => "ES256", "typ" => "dpop+jwt"}
      # JOSE.JWT.sign needs a key, so sign with a proper header then remove
      # the jwk from the protected header.
      signed_proof = sign_proof(key, build_header(public_map(key)), build_claims())
      [_, payload, sig] = String.split(signed_proof, ".")
      header_b64 = header |> JSON.encode!() |> Base.url_encode64(padding: false)
      proof = Enum.join([header_b64, payload, sig], ".")

      assert {:error, :missing_jwk} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects proof whose jwk is an empty map" do
      key = gen_ec_key()
      header = %{"alg" => "ES256", "jwk" => %{}, "typ" => "dpop+jwt"}
      signed_proof = sign_proof(key, build_header(public_map(key)), build_claims())
      [_, payload, sig] = String.split(signed_proof, ".")
      header_b64 = header |> JSON.encode!() |> Base.url_encode64(padding: false)
      proof = Enum.join([header_b64, payload, sig], ".")

      assert {:error, :missing_jwk} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects proof whose jwk carries EC private-key material (d)" do
      key = gen_ec_key()
      {_, priv_map} = JOSE.JWK.to_map(key)
      assert Map.has_key?(priv_map, "d")
      header = build_header(priv_map)
      proof = sign_proof(key, header, build_claims())

      assert {:error, :invalid_jwk} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects proof whose jwk smuggles any private-key member" do
      # RFC 7518 §6.2.2 / §6.3.2 private components. Splice each one into an
      # otherwise-valid public JWK so the rejection is attributable to the
      # private member, not to a malformed key.
      key = gen_ec_key()
      pub_map = public_map(key)
      signed_proof = sign_proof(key, build_header(pub_map), build_claims())
      [_, payload, sig] = String.split(signed_proof, ".")

      for member <- ~w(d p q dp dq qi oth k) do
        smuggled = Map.put(pub_map, member, "x")
        header_b64 = build_header(smuggled) |> JSON.encode!() |> Base.url_encode64(padding: false)
        proof = Enum.join([header_b64, payload, sig], ".")

        assert {:error, :invalid_jwk} = DPoP.verify_proof(proof, base_opts()),
               "expected :invalid_jwk for smuggled member #{member}"
      end
    end

    test "rejects proof with an unparseable jwk" do
      key = gen_ec_key()
      header = build_header(%{"crv" => "P-256", "kty" => "EC"})
      signed_proof = sign_proof(key, build_header(public_map(key)), build_claims())
      [_, payload, sig] = String.split(signed_proof, ".")
      header_b64 = header |> JSON.encode!() |> Base.url_encode64(padding: false)
      proof = Enum.join([header_b64, payload, sig], ".")

      assert {:error, reason} = DPoP.verify_proof(proof, base_opts())
      # An incomplete JWK either fails JOSE.JWK.from_map (-> :invalid_jwk),
      # blows up inside verify_strict (-> :invalid_proof catch-all), or - if
      # JOSE coerces it into a valid struct - fails signature verification
      # (-> :invalid_signature). Every branch is a closed failure.
      assert reason in [:invalid_jwk, :invalid_signature, :invalid_proof]
    end
  end

  # -----------------------------------------------------------------
  # signature checks
  # -----------------------------------------------------------------

  describe "verify_proof/2 signature checks" do
    test "rejects a proof signed with a different key than the embedded jwk" do
      signer = gen_ec_key()
      embedded = gen_ec_key()

      header = build_header(public_map(embedded))
      proof = sign_proof(signer, header, build_claims())

      assert {:error, :invalid_signature} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects a proof whose payload is tampered post-signing" do
      {proof, _key, _claims, _header} = valid_proof()
      [h, _p, s] = String.split(proof, ".")

      tampered_payload =
        build_claims(%{"htm" => "GET"})
        |> JSON.encode!()
        |> Base.url_encode64(padding: false)

      tampered = Enum.join([h, tampered_payload, s], ".")

      assert {:error, :invalid_signature} = DPoP.verify_proof(tampered, base_opts())
    end
  end

  # -----------------------------------------------------------------
  # claim validation: htm
  # -----------------------------------------------------------------

  describe "verify_proof/2 htm validation" do
    test "rejects htm mismatch" do
      {proof, _jkt} = Factory.dpop_proof(htm: "GET")
      assert {:error, :invalid_htm} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects missing htm" do
      key = gen_ec_key()
      claims = %{"htu" => @http_uri, "iat" => unix_now(), "jti" => "j1"}
      proof = sign_proof(key, build_header(public_map(key)), claims)

      assert {:error, :invalid_htm} = DPoP.verify_proof(proof, base_opts())
    end

    test "htm comparison is case-sensitive (RFC 9449 §4.3)" do
      {proof, _jkt} = Factory.dpop_proof(htm: "post")
      assert {:error, :invalid_htm} = DPoP.verify_proof(proof, base_opts())
    end
  end

  # -----------------------------------------------------------------
  # claim validation: htu
  # -----------------------------------------------------------------

  describe "verify_proof/2 htu validation" do
    test "rejects htu mismatch (different path)" do
      {proof, _jkt} = Factory.dpop_proof(htu: "https://api.example.com/other")
      assert {:error, :invalid_htu} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects htu mismatch (different host)" do
      {proof, _jkt} = Factory.dpop_proof(htu: "https://evil.example/oauth/token")
      assert {:error, :invalid_htu} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects missing htu" do
      key = gen_ec_key()
      claims = %{"htm" => @http_method, "iat" => unix_now(), "jti" => "j1"}
      proof = sign_proof(key, build_header(public_map(key)), claims)

      assert {:error, :invalid_htu} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects htu when the proof's claim is http:// (downgrade)" do
      http_uri = "http://api.example.com/oauth/token"
      {proof, _jkt} = Factory.dpop_proof(htu: http_uri)

      assert {:error, :invalid_htu} = DPoP.verify_proof(proof, base_opts(http_uri: http_uri))
    end

    test "rejects htu when the live request URI is http:// (downgrade)" do
      live_uri = "http://api.example.com/oauth/token"
      {proof, _jkt} = Factory.dpop_proof()

      assert {:error, :invalid_htu} = DPoP.verify_proof(proof, base_opts(http_uri: live_uri))
    end

    test "rejects htu with other non-https schemes (ws://, file://, javascript:)" do
      for scheme <- ["ws://", "wss://", "file://", "javascript:"] do
        uri = scheme <> "api.example.com/oauth/token"
        {proof, _jkt} = Factory.dpop_proof(htu: uri)

        assert {:error, :invalid_htu} = DPoP.verify_proof(proof, base_opts(http_uri: uri)),
               "expected :invalid_htu for #{uri}"
      end
    end

    test "query and fragment are ignored for htu comparison" do
      {clean, _jkt} = Factory.dpop_proof(htu: "https://api.example.com/x")

      assert {:ok, _} =
               DPoP.verify_proof(clean, base_opts(http_uri: "https://api.example.com/x#section"))

      {with_query_and_fragment, _jkt} =
        Factory.dpop_proof(htu: "https://api.example.com/x?cb=1#section")

      assert {:ok, _} =
               DPoP.verify_proof(
                 with_query_and_fragment,
                 base_opts(http_uri: "https://api.example.com/x")
               )
    end

    test "normalizes scheme/host case and the default HTTPS port" do
      {upper_case, _jkt} = Factory.dpop_proof(htu: "HTTPS://API.EXAMPLE.COM/oauth/token")

      assert {:ok, _} =
               DPoP.verify_proof(upper_case, base_opts(http_uri: "https://api.example.com/oauth/token"))

      {default_port, _jkt} = Factory.dpop_proof(htu: "https://api.example.com:443/oauth/token")

      assert {:ok, _} =
               DPoP.verify_proof(default_port, base_opts(http_uri: "https://api.example.com/oauth/token"))
    end

    test "still rejects non-default port mismatches" do
      {proof, _jkt} = Factory.dpop_proof(htu: "https://api.example.com:444/oauth/token")

      assert {:error, :invalid_htu} =
               DPoP.verify_proof(proof, base_opts(http_uri: "https://api.example.com/oauth/token"))
    end
  end

  # -----------------------------------------------------------------
  # claim validation: iat
  # -----------------------------------------------------------------

  describe "verify_proof/2 iat validation" do
    test "rejects iat older than max_age_seconds (default 60)" do
      iat = unix_now() - 120
      {proof, _jkt} = Factory.dpop_proof(iat: iat)

      assert {:error, :proof_expired} = DPoP.verify_proof(proof, base_opts())
    end

    test "honors a custom :max_age_seconds" do
      iat = unix_now() - 120
      {proof, _jkt} = Factory.dpop_proof(iat: iat)

      assert {:ok, _} = DPoP.verify_proof(proof, base_opts(max_age_seconds: 300))
    end

    test "rejects iat too far in the future" do
      iat = unix_now() + 600
      {proof, _jkt} = Factory.dpop_proof(iat: iat)

      assert {:error, :invalid_iat} = DPoP.verify_proof(proof, base_opts())
    end

    test "tolerates small future-clock skew on iat" do
      iat = unix_now() + 10
      {proof, _jkt} = Factory.dpop_proof(iat: iat)

      assert {:ok, _} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects missing iat" do
      key = gen_ec_key()
      claims = %{"htm" => @http_method, "htu" => @http_uri, "jti" => "j1"}
      proof = sign_proof(key, build_header(public_map(key)), claims)

      assert {:error, :missing_iat} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects iat that is not an integer" do
      {proof, _, _, _} = valid_proof(claim_overrides: %{"iat" => "soon"})
      assert {:error, :invalid_iat} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects iat that is negative" do
      {proof, _, _, _} = valid_proof(claim_overrides: %{"iat" => -1})
      assert {:error, :invalid_iat} = DPoP.verify_proof(proof, base_opts())
    end
  end

  # -----------------------------------------------------------------
  # claim validation: jti
  # -----------------------------------------------------------------

  describe "verify_proof/2 jti validation" do
    test "rejects missing jti" do
      key = gen_ec_key()
      claims = %{"htm" => @http_method, "htu" => @http_uri, "iat" => unix_now()}
      proof = sign_proof(key, build_header(public_map(key)), claims)

      assert {:error, :missing_jti} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects empty-string jti" do
      {proof, _, _, _} = valid_proof(claim_overrides: %{"jti" => ""})
      assert {:error, :invalid_jti} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects non-binary jti" do
      {proof, _, _, _} = valid_proof(claim_overrides: %{"jti" => 42})
      assert {:error, :invalid_jti} = DPoP.verify_proof(proof, base_opts())
    end

    test "accepts a jti at the 256-byte cap" do
      jti = String.duplicate("a", 256)
      {proof, _jkt} = Factory.dpop_proof(jti: jti)

      assert {:ok, %{jti: ^jti}} = DPoP.verify_proof(proof, base_opts())
    end

    test "rejects jti larger than the 256-byte cap (memory-exhaustion guard)" do
      oversized = String.duplicate("a", 257)
      {proof, _jkt} = Factory.dpop_proof(jti: oversized)

      assert {:error, :invalid_jti} = DPoP.verify_proof(proof, base_opts())
    end
  end

  # -----------------------------------------------------------------
  # access-token binding: ath
  # -----------------------------------------------------------------

  describe "verify_proof/2 access-token binding (ath)" do
    test "missing ath when :access_token is provided rejects" do
      {proof, _jkt} = Factory.dpop_proof()

      assert {:error, :missing_ath} =
               DPoP.verify_proof(proof, base_opts(access_token: "atk_xyz"))
    end

    test "ath mismatch rejects" do
      access_token = "atk_real"
      {proof, _jkt} = Factory.dpop_proof(ath: DPoP.compute_ath("atk_other"))

      assert {:error, :invalid_ath} =
               DPoP.verify_proof(proof, base_opts(access_token: access_token))
    end

    test "ath compare is length-gated: a wrong-length ath is rejected, not crashed" do
      # The verifier gates :crypto.hash_equals on equal length first, since
      # ath is attacker-controlled and hash_equals raises on length mismatch.
      access_token = "atk_real"
      {proof, _jkt} = Factory.dpop_proof(ath: "short")

      assert {:error, :invalid_ath} =
               DPoP.verify_proof(proof, base_opts(access_token: access_token))
    end

    test "ath present without :access_token is returned as-is, not enforced" do
      ath = DPoP.compute_ath("atk_some")
      {proof, _jkt} = Factory.dpop_proof(ath: ath)

      assert {:ok, %{ath: ^ath}} = DPoP.verify_proof(proof, base_opts())
    end

    test "non-binary ath (without :access_token) is rejected" do
      {proof, _, _, _} = valid_proof(claim_overrides: %{"ath" => 42})
      assert {:error, :invalid_ath} = DPoP.verify_proof(proof, base_opts())
    end
  end

  # -----------------------------------------------------------------
  # malformed input
  # -----------------------------------------------------------------

  describe "verify_proof/2 malformed input" do
    test "non-binary input returns :invalid_proof" do
      for bad <- [nil, 42, %{}, :atom, ["a", "b"]] do
        assert {:error, :invalid_proof} = DPoP.verify_proof(bad, base_opts()),
               "expected :invalid_proof for #{inspect(bad)}"
      end
    end

    test "empty string returns :invalid_proof" do
      assert {:error, :invalid_proof} = DPoP.verify_proof("", base_opts())
    end

    test "garbage that isn't a JWS-shaped string returns :invalid_proof" do
      for bad <- ["not-a-jwt", "only.two", "four.parts.are.bad", "!!!.@@@.###"] do
        assert {:error, :invalid_proof} = DPoP.verify_proof(bad, base_opts()),
               "expected :invalid_proof for #{inspect(bad)}"
      end
    end
  end

  # -----------------------------------------------------------------
  # required opts
  # -----------------------------------------------------------------

  describe "verify_proof/2 required opts" do
    test "raises if :http_method is missing" do
      {proof, _jkt} = Factory.dpop_proof()

      assert_raise ArgumentError, ~r/:http_method/, fn ->
        DPoP.verify_proof(proof, http_uri: @http_uri)
      end
    end

    test "raises if :http_uri is missing" do
      {proof, _jkt} = Factory.dpop_proof()

      assert_raise ArgumentError, ~r/:http_uri/, fn ->
        DPoP.verify_proof(proof, http_method: @http_method)
      end
    end

    test "raises if :http_method is empty string" do
      {proof, _jkt} = Factory.dpop_proof()

      assert_raise ArgumentError, ~r/:http_method/, fn ->
        DPoP.verify_proof(proof, http_method: "", http_uri: @http_uri)
      end
    end
  end

  # -----------------------------------------------------------------
  # compute_jkt/1
  # -----------------------------------------------------------------

  describe "compute_jkt/1" do
    test "returns the RFC 7638 SHA-256 thumbprint of a JOSE.JWK" do
      key = gen_ec_key()
      assert DPoP.compute_jkt(key) == JOSE.JWK.thumbprint(key)
    end

    test "accepts a plain-map JWK (public key shape from a DPoP header)" do
      key = gen_ec_key()
      pub_map = public_map(key)

      assert DPoP.compute_jkt(pub_map) == JOSE.JWK.thumbprint(key)
    end

    test "compute_jkt(map) == compute_jkt(jwk) for the same key" do
      key = gen_ec_key()
      pub_map = public_map(key)

      assert DPoP.compute_jkt(key) == DPoP.compute_jkt(pub_map)
    end
  end

  # -----------------------------------------------------------------
  # compute_ath/1
  # -----------------------------------------------------------------

  describe "compute_ath/1" do
    test "returns the base64url-encoded SHA-256 of the access token, unpadded" do
      token = "atk_test"
      expected = :crypto.hash(:sha256, token) |> Base.url_encode64(padding: false)

      assert DPoP.compute_ath(token) == expected
    end

    test "different tokens produce different ath values" do
      refute DPoP.compute_ath("atk_a") == DPoP.compute_ath("atk_b")
    end
  end

  # -----------------------------------------------------------------
  # dpop_bound?/1
  # -----------------------------------------------------------------

  describe "dpop_bound?/1" do
    test "true for claims with cnf.jkt as a non-empty string" do
      assert DPoP.dpop_bound?(%{"cnf" => %{"jkt" => "thumb"}})
    end

    test "false for claims without cnf" do
      refute DPoP.dpop_bound?(%{"sub" => "oc_x"})
    end

    test "false for claims with cnf but no jkt" do
      refute DPoP.dpop_bound?(%{"cnf" => %{"x5t#S256" => "thumb"}})
    end

    test "false for cnf.jkt that is empty or non-string" do
      refute DPoP.dpop_bound?(%{"cnf" => %{"jkt" => ""}})
      refute DPoP.dpop_bound?(%{"cnf" => %{"jkt" => 42}})
      refute DPoP.dpop_bound?(%{"cnf" => %{"jkt" => nil}})
    end
  end

  # -----------------------------------------------------------------
  # replay protection (:replay_check)
  # -----------------------------------------------------------------

  describe "verify_proof/2 replay protection (:replay_check)" do
    test "calls :replay_check exactly once on the happy path with the proof's jti and a ttl" do
      jti = "jti-#{System.unique_integer([:positive])}"
      {proof, _jkt} = Factory.dpop_proof(jti: jti)
      parent = self()

      replay_check = fn seen, ttl ->
        send(parent, {:replay_check_called, seen, ttl})
        :ok
      end

      assert {:ok, %{jti: ^jti}} =
               DPoP.verify_proof(proof, base_opts(replay_check: replay_check))

      # The verifier passes the acceptance window (default max_age 60 +
      # future skew 60) as the TTL the cache must remember the jti for.
      assert_received {:replay_check_called, ^jti, 120}
      # Exactly once.
      refute_received {:replay_check_called, _, _}
    end

    test "passes a ttl derived from a custom :max_age_seconds" do
      parent = self()
      {proof, _jkt} = Factory.dpop_proof()
      replay_check = fn _jti, ttl -> send(parent, {:ttl, ttl}) && :ok end

      assert {:ok, _} =
               DPoP.verify_proof(proof, base_opts(max_age_seconds: 300, replay_check: replay_check))

      assert_received {:ttl, 360}
    end

    test "rejects the request when :replay_check returns {:error, :replay}" do
      {proof, _jkt} = Factory.dpop_proof()
      replay_check = fn _jti, _ttl -> {:error, :replay} end

      assert {:error, :replay} =
               DPoP.verify_proof(proof, base_opts(replay_check: replay_check))
    end

    test ":replay_check is NOT consulted when an earlier check would fail" do
      parent = self()
      replay_check = fn jti, _ttl -> send(parent, {:should_not_run, jti}) end

      # Bad htm so the request fails before reaching replay.
      {proof, _jkt} = Factory.dpop_proof(htm: "DELETE")

      assert {:error, :invalid_htm} =
               DPoP.verify_proof(proof, base_opts(replay_check: replay_check))

      refute_received {:should_not_run, _}
    end

    test "raises if :replay_check returns an unsupported value" do
      {proof, _jkt} = Factory.dpop_proof()
      bogus = fn _jti, _ttl -> :random_unexpected_value end

      assert_raise ArgumentError, ~r/:replay_check/, fn ->
        DPoP.verify_proof(proof, base_opts(replay_check: bogus))
      end
    end

    test "raises if :replay_check is not a 2-arity function" do
      {proof, _jkt} = Factory.dpop_proof()

      for bad <- [42, "not-a-fun", fn -> :ok end, fn _a -> :ok end] do
        assert_raise ArgumentError, ~r/:replay_check/, fn ->
          DPoP.verify_proof(proof, base_opts(replay_check: bad))
        end
      end
    end
  end

  defp enable_ed448_support do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end
end

defmodule Attesto.DPoP.ReplayCacheIntegrationTest do
  @moduledoc false
  # The ReplayCache is a named ETS-backed GenServer singleton; starting it
  # mutates VM-global state, so this suite is async: false and starts the
  # cache under the test supervisor.
  use ExUnit.Case, async: false

  alias Attesto.DPoP
  alias Attesto.DPoP.ReplayCache
  alias Attesto.Test.Factory

  @http_method "POST"
  @http_uri "https://api.example.com/oauth/token"

  setup do
    start_supervised!({ReplayCache, ttl_seconds: 60, multi_node_acknowledged?: true})
    :ok
  end

  defp base_opts(extra) do
    Keyword.merge([http_method: @http_method, http_uri: @http_uri], extra)
  end

  test "a second proof with the same jti is rejected as :replay" do
    jti = "replay-test-#{System.unique_integer([:positive])}"
    {proof, _jkt} = Factory.dpop_proof(jti: jti)

    replay_check = &ReplayCache.check_and_record/2

    assert {:ok, %{jti: ^jti}} =
             DPoP.verify_proof(proof, base_opts(replay_check: replay_check))

    assert {:error, :replay} =
             DPoP.verify_proof(proof, base_opts(replay_check: replay_check))
  end

  test "distinct jtis both pass and the cache records each once" do
    {proof1, _} = Factory.dpop_proof(jti: "jti-a-#{System.unique_integer([:positive])}")
    {proof2, _} = Factory.dpop_proof(jti: "jti-b-#{System.unique_integer([:positive])}")
    replay_check = &ReplayCache.check_and_record/2

    before = ReplayCache.size()
    assert {:ok, _} = DPoP.verify_proof(proof1, base_opts(replay_check: replay_check))
    assert {:ok, _} = DPoP.verify_proof(proof2, base_opts(replay_check: replay_check))
    assert ReplayCache.size() == before + 2
  end

  test "check_and_record/1 reports :ok then {:error, :replay} for the same jti" do
    jti = "direct-#{System.unique_integer([:positive])}"
    assert :ok = ReplayCache.check_and_record(jti)
    assert {:error, :replay} = ReplayCache.check_and_record(jti)
  end
end
