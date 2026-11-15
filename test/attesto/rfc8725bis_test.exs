defmodule Attesto.RFC8725BisTest do
  @moduledoc false
  # Factory.config/2 mutates the global Attesto.Keystore.Static app env, so run serially.
  use ExUnit.Case, async: false

  alias Attesto.{
    DPoP,
    JWE,
    JWS,
    Key,
    SdJwtVc,
    SigningAlg,
    StatusList,
    Token
  }

  alias Attesto.Test.Factory

  setup do
    pem = Factory.ec_pem()
    config = Factory.config(pem)
    {_kty, pub} = pem |> Key.jwk() |> JOSE.JWK.to_public_map()
    pub_sig = Map.merge(pub, %{"kid" => Key.kid(pem), "alg" => "ES256", "use" => "sig"})
    jwks = %{"keys" => [pub_sig]}

    enc_priv = JOSE.JWK.generate_key({:ec, "P-256"})
    {_m, enc_pub} = JOSE.JWK.to_public_map(enc_priv)

    %{pem: pem, config: config, pub_sig: pub_sig, jwks: jwks, enc_priv: enc_priv, enc_pub: enc_pub}
  end

  test "1. alg comparison is strictly case-sensitive across JWS, JWE, and policy", ctx do
    refute SigningAlg.valid_verification_algorithms?(["es256"])
    refute SigningAlg.valid_verification_algorithms?(["nOnE"])
    refute SigningAlg.valid_verification_algorithms?(["hs256"])

    claims = valid_at_claims(ctx.config)

    for bad_alg <- ["es256", "Es256", "HS256", "hs256", "none", "NONE"] do
      token =
        JWS.sign_compact(
          ctx.pem,
          %{"alg" => "ES256", "kid" => Key.kid(ctx.pem), "typ" => "at+jwt"},
          claims
        )

      [_hdr, payload, sig] = String.split(token, ".")
      forged_hdr = %{"alg" => bad_alg, "kid" => Key.kid(ctx.pem), "typ" => "at+jwt"} |> JSON.encode!() |> JWS.encode64()
      assert {:error, _} = Token.verify(ctx.config, "#{forged_hdr}.#{payload}.#{sig}")
    end

    assert {:ok, encrypted} =
             JWE.encrypt(ctx.enc_pub, "secret", %{"alg" => "ECDH-ES", "enc" => "A256GCM"})

    [_ehdr | rest] = String.split(encrypted, ".")
    lower_hdr = %{"alg" => "ecdh-es", "enc" => "A256GCM"} |> JSON.encode!() |> JWS.encode64()
    assert {:error, :invalid_header} = JWE.decrypt(ctx.enc_priv, Enum.join([lower_hdr | rest], "."))
  end

  test "2. encryption-signature confusion: JWS and JWE formats and key uses are strictly separated", ctx do
    {:ok, %{access_token: jws}} =
      Token.mint(
        ctx.config,
        %{kind: "client", sub: "oc_1", scopes: [], claims: %{"client_id" => "oc_1"}}
      )

    {:ok, jwe} =
      JWE.encrypt(ctx.enc_pub, "payload", %{"alg" => "ECDH-ES", "enc" => "A256GCM"})

    assert {:error, :invalid_token} = Token.verify(ctx.config, jwe)
    assert {:error, :malformed} = JWS.protected_header(jwe)
    assert {:error, :invalid_jwe} = JWE.decrypt(ctx.enc_priv, jws)

    enc_marked_pub = Map.put(ctx.pub_sig, "use", "enc")
    assert JWS.verification_candidates([enc_marked_pub]) == []

    assert {:error, :invalid_key} =
             JWE.encrypt(ctx.pub_sig, "payload", %{"alg" => "ECDH-ES", "enc" => "A256GCM"})
  end

  test "3. PBES2 excessive p2c iteration counts are refused immediately (PBES2 is not accepted)", ctx do
    header = %{"alg" => "PBES2-HS256+A128KW", "enc" => "A256GCM", "p2c" => 10_000_000, "p2s" => JWS.encode64("salt")}
    compact = "#{JWS.encode64(JSON.encode!(header))}.Zm9v.AAAAAAAAAAAA.Zm9v.AAAAAAAAAAAAAAAAAAAAAA"

    assert {:error, :invalid_header} = JWE.decrypt(ctx.enc_priv, compact)
  end

  test "4. serialization-format confusion: non-compact JSON or padded inputs are rejected", ctx do
    {:ok, %{access_token: token}} =
      Token.mint(ctx.config, %{kind: "client", sub: "oc_1", scopes: [], claims: %{"client_id" => "oc_1"}})

    [h, p, s] = String.split(token, ".")

    json_jws = JSON.encode!(%{"protected" => h, "payload" => p, "signature" => s})
    padded = "#{h}=." <> p <> "." <> s
    with_space = " " <> token
    two_parts = "#{h}.#{p}"
    four_parts = "#{h}.#{p}.#{s}.extra"

    for bad <- [json_jws, padded, with_space, two_parts, four_parts] do
      assert {:error, _} = JWS.decode_compact(bad), "expected JWS.decode_compact to reject #{inspect(bad)}"
      assert {:error, _} = Token.verify(ctx.config, bad), "expected Token.verify to reject #{inspect(bad)}"
      assert {:error, :invalid_jwe} = JWE.decrypt(ctx.enc_priv, bad)
    end

    assert {:ok, _} = Token.verify(ctx.config, token)
  end

  test "5. JWE compression (zip header) is rejected prior to decompression", ctx do
    {_, compressed_jwe} =
      JOSE.JWE.block_encrypt(
        {JOSE.JWK.from_map(ctx.enc_pub), JOSE.JWK.generate_key({:ec, "P-256"})},
        "compressed-payload",
        %{"alg" => "ECDH-ES", "enc" => "A256GCM", "zip" => "DEF"}
      )
      |> JOSE.JWE.compact()

    assert {:error, :invalid_header} = JWE.decrypt(ctx.enc_priv, compressed_jwe)
  end

  test "6. explicit typing rejects cross-JWT confusion and normalizes RFC 7515 application/ prefix", ctx do
    now = System.system_time(:second)

    status_jwt =
      JWS.sign_compact(
        ctx.pem,
        %{"alg" => "ES256", "kid" => Key.kid(ctx.pem), "typ" => "application/statuslist+jwt"},
        %{"sub" => "https://issuer.example/status/1", "iat" => now, "status_list" => StatusList.build([0, 1])}
      )

    assert {:ok, _} = StatusList.verify(status_jwt, ctx.jwks, now: now)

    wrong_typ_at =
      JWS.sign_compact(
        ctx.pem,
        %{"alg" => "ES256", "kid" => Key.kid(ctx.pem), "typ" => "logout+jwt"},
        valid_at_claims(ctx.config)
      )

    assert {:error, :invalid_typ} = Token.verify(ctx.config, wrong_typ_at)

    sd_jwt =
      SdJwtVc.issue(
        iss: ctx.config.issuer,
        vct: "urn:example:id",
        pem: ctx.pem,
        typ: "dc+sd-jwt"
      )

    [issuer_jwt, ""] = String.split(sd_jwt, "~")
    {:ok, %{payload_segment: payload_seg}} = JWS.decode_compact(issuer_jwt)
    {:ok, payload_json} = JWS.decode64(payload_seg)
    {:ok, sd_claims} = JSON.decode(payload_json)

    resigned =
      JWS.sign_compact(
        ctx.pem,
        %{"alg" => "ES256", "kid" => Key.kid(ctx.pem), "typ" => "application/dc+sd-jwt"},
        sd_claims
      )

    assert {:ok, _} = SdJwtVc.verify(resigned <> "~", ctx.jwks)
  end

  test "7. untrusted jku, x5u, and unknown kid header parameters do not trigger fetches or bypass key lookup", ctx do
    hostile_header = %{
      "alg" => "ES256",
      "kid" => "unknown-kid",
      "jku" => "http://127.0.0.1:1/jwks.json",
      "x5u" => "http://127.0.0.1:1/cert.pem",
      "typ" => "at+jwt"
    }

    forged = JWS.sign_compact(ctx.pem, hostile_header, valid_at_claims(ctx.config))
    assert {:error, :invalid_signature} = Token.verify(ctx.config, forged)
  end

  test "8. alg: none is absent from default allowlists and rejected everywhere without explicit opt-in", ctx do
    refute "none" in SigningAlg.allowed()
    refute SigningAlg.valid_verification_algorithms?(["none"])
    refute SigningAlg.valid_verification_algorithms?(["ES256", "none"])

    claims = valid_at_claims(ctx.config)
    hdr = %{"alg" => "none", "typ" => "at+jwt"} |> JSON.encode!() |> JWS.encode64()
    pay = claims |> JSON.encode!() |> JWS.encode64()
    unsigned = "#{hdr}.#{pay}."

    assert {:error, _} = Token.verify(ctx.config, unsigned)
    assert {:error, _} = StatusList.verify(unsigned, ctx.jwks)
    assert {:error, _} = DPoP.verify_proof(unsigned, htm: "GET", htu: "https://rs.example/r")
  end

  defp valid_at_claims(config) do
    now = System.system_time(:second)

    %{
      "iss" => config.issuer,
      "aud" => config.audience,
      "sub" => "oc_1",
      "client_id" => "oc_1",
      "principal_kind" => "client",
      "scope" => "read",
      "jti" => "jti-1",
      "iat" => now,
      "exp" => now + 300,
      "typ" => "at"
    }
  end
end
