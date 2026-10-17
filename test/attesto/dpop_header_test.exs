defmodule Attesto.DPoPHeaderTest do
  @moduledoc false
  # DPoP proof-header validation gaps, benchmarked against the behaviour
  # of panva/jose and node-oidc-provider. Two axes:
  #
  #   1. `crit` handling. RFC 7515 §4.1.11 says a recipient that does not
  #      understand a parameter named in `crit` MUST reject the JWS.
  #      Attesto understands NO `crit` extensions, so `verify_proof/2`
  #      rejects ANY header carrying a `crit` member at all - regardless of
  #      what (if anything) the list names, and even when `crit` is empty or
  #      not a list. The reject reason is :unsupported_critical_header.
  #
  #   2. Embedded-JWK metadata sanity. RFC 9449 §4.2 says the embedded
  #      `jwk` MUST be a public ASYMMETRIC SIGNING key. Attesto rejects
  #      private-key material (members d/p/q/dp/dq/qi/oth/k) and pins the
  #      signature `alg` to an asymmetric whitelist, but it does NOT inspect
  #      the JWK's `use` / `key_ops` / embedded `alg` metadata. These tests
  #      pin Attesto's CURRENT behaviour for each metadata-mismatch shape so
  #      a regression (in either direction) is visible. Cases where a
  #      clearly-wrong-for-signing key is ACCEPTED are flagged in the task's
  #      source_bugs output.
  #
  # Every assertion here drives the pure function `DPoP.verify_proof/2`
  # with no keystore and no app env, so the module is async-safe.
  use ExUnit.Case, async: true

  alias Attesto.DPoP
  alias Attesto.Test.DPoPFixtures

  @http_method "POST"
  @http_uri "https://api.example.com/oauth/token"

  # -----------------------------------------------------------------
  # helpers
  # -----------------------------------------------------------------

  defp unix_now, do: DPoPFixtures.now()
  defp gen_ec_key, do: DPoPFixtures.ec_key()
  defp gen_rsa_key, do: DPoPFixtures.rsa_key()
  defp public_map(key), do: DPoPFixtures.public_map(key)

  defp claims(overrides \\ %{}) do
    DPoPFixtures.claims(@http_method, @http_uri, unix_now(), overrides)
  end

  # `now` is pinned so a slow run never drifts the proof out of the iat
  # window; every verify in this module reuses the same reference clock.
  defp verify_opts(extra \\ []) do
    DPoPFixtures.verification_options(
      @http_method,
      @http_uri,
      Keyword.put_new(extra, :now, unix_now())
    )
  end

  # Sign a proof normally: JOSE picks the wire `alg` from `header["alg"]`,
  # so the signature is genuinely consistent with the header alg.
  defp sign(key, header) do
    DPoPFixtures.sign(key, header, claims())
  end

  defp base_header(jwk_map, overrides \\ %{}) do
    DPoPFixtures.header(jwk_map, overrides)
  end

  # Forge a compact JWS whose PROTECTED HEADER differs from the one that
  # was actually signed, while reusing a real signature segment. Used for
  # alg-confusion variants (lie about `alg` in the header) and for a
  # non-list `crit` value, which `JOSE.JWT.sign/3` would refuse to emit.
  # The point of each such test is which check fires FIRST, so a mismatched
  # signature on the swapped header is fine.
  defp reheader(signed_compact, new_header_map) do
    DPoPFixtures.reheader(signed_compact, new_header_map)
  end

  # =================================================================
  # (1) crit handling
  # =================================================================

  describe "crit protected-header parameter is always rejected" do
    setup do
      key = gen_ec_key()
      {:ok, key: key, jwk_map: public_map(key)}
    end

    test "crit:[\"b64\"] with b64:false (a real JOSE extension Attesto does not negotiate)",
         %{key: key, jwk_map: jwk_map} do
      # node-oidc-provider / panva/jose would process `b64` (RFC 7797) only
      # if it were in their understood set; Attesto understands none, so a
      # b64 critical header is a hard reject before the signature is trusted.
      proof = sign(key, base_header(jwk_map, %{"crit" => ["b64"], "b64" => false}))

      assert {:error, :unsupported_critical_header} =
               DPoP.verify_proof(proof, verify_opts())
    end

    test "crit:[\"urn:example:unknown\"] naming an extension Attesto does not implement",
         %{key: key, jwk_map: jwk_map} do
      proof =
        sign(
          key,
          base_header(jwk_map, %{"crit" => ["urn:example:unknown"], "urn:example:unknown" => true})
        )

      assert {:error, :unsupported_critical_header} =
               DPoP.verify_proof(proof, verify_opts())
    end

    test "crit:[] (empty list) is rejected even though it names nothing",
         %{key: key, jwk_map: jwk_map} do
      # RFC 7515 §4.1.11 actually forbids an empty `crit`; Attesto rejects on
      # mere presence (Map.has_key?), so the malformed-empty case is covered
      # by the same guard. Document that this is NOT accepted.
      proof = sign(key, base_header(jwk_map, %{"crit" => []}))

      assert {:error, :unsupported_critical_header} =
               DPoP.verify_proof(proof, verify_opts())
    end

    test "crit as a non-list (a bare string) is rejected on presence alone",
         %{key: key, jwk_map: jwk_map} do
      # `JOSE.JWT.sign/3` will not emit a non-list `crit`, so forge the
      # header by hand on top of a real signature. Attesto's presence check
      # fires before any signature math, so the swapped-out signature is
      # irrelevant to the :unsupported_critical_header outcome.
      signed = sign(key, base_header(jwk_map))
      forged = reheader(signed, base_header(jwk_map, %{"crit" => "b64"}))

      assert {:error, :unsupported_critical_header} =
               DPoP.verify_proof(forged, verify_opts())
    end

    test "the same proof WITHOUT crit verifies (control)", %{key: key, jwk_map: jwk_map} do
      proof = sign(key, base_header(jwk_map))

      assert {:ok, %{htm: @http_method, htu: @http_uri}} =
               DPoP.verify_proof(proof, verify_opts())
    end
  end

  # =================================================================
  # (2) embedded-JWK metadata mismatch
  #
  # Each test documents Attesto's CURRENT behaviour precisely. Where a
  # clearly-wrong-for-signing JWK is ACCEPTED, the assertion is on
  # {:ok, _} and the test name says "ACCEPTED (gap)".
  # =================================================================

  describe "embedded jwk use/key_ops metadata is enforced" do
    test "use:\"enc\" key is rejected (RFC 7517 §4.2: not a signing key)" do
      # An encryption-use public key presented to sign a DPoP proof: `use`
      # is "enc", so the key is declared for encryption, not signatures.
      # Attesto refuses to verify a proof against a key whose own metadata
      # says it is not for signing.
      key = gen_ec_key()
      jwk_map = public_map(key) |> Map.put("use", "enc")
      proof = sign(key, base_header(jwk_map))

      assert {:error, :invalid_jwk} = DPoP.verify_proof(proof, verify_opts())
    end

    test ~s{key_ops:["encrypt"] (no "verify") is rejected (RFC 7517 §4.3)} do
      # A key whose declared operations are {encrypt} and explicitly NOT
      # {verify} must not be honoured for signature verification.
      key = gen_ec_key()
      jwk_map = public_map(key) |> Map.put("key_ops", ["encrypt"])
      proof = sign(key, base_header(jwk_map))

      assert {:error, :invalid_jwk} = DPoP.verify_proof(proof, verify_opts())
    end

    test "key_ops:[\"verify\"] (the correct op) is ACCEPTED (expected)" do
      key = gen_ec_key()
      jwk_map = public_map(key) |> Map.put("key_ops", ["verify"])
      proof = sign(key, base_header(jwk_map))

      assert {:ok, _result} = DPoP.verify_proof(proof, verify_opts())
    end
  end

  describe "embedded jwk alg vs header alg" do
    test ~s{jwk alg:"ES384" contradicting header alg:"ES256" is rejected (RFC 7517 §4.4)} do
      # The embedded key declares ES384 while the JWS header (and the actual
      # signature) is ES256. The JWK `alg` constrains which algorithm the
      # key may be used with, so the contradiction is rejected.
      key = gen_ec_key()
      jwk_map = public_map(key) |> Map.put("alg", "ES384")
      proof = sign(key, base_header(jwk_map, %{"alg" => "ES256"}))

      assert {:error, :invalid_jwk} = DPoP.verify_proof(proof, verify_opts())
    end

    test "jwk alg matching header alg (ES256/ES256) is ACCEPTED (expected)" do
      key = gen_ec_key()
      jwk_map = public_map(key) |> Map.put("alg", "ES256")
      proof = sign(key, base_header(jwk_map, %{"alg" => "ES256"}))

      assert {:ok, _result} = DPoP.verify_proof(proof, verify_opts())
    end
  end

  describe "key-type vs header-alg confusion is rejected before signature verification" do
    test "an EC jwk presented under an RSA header alg is :invalid_jwk" do
      # Sign a real ES256 proof, then rewrite the protected header to claim
      # alg:RS256 while keeping the EC jwk. verify_strict pins [\"RS256\"];
      # the raw JWK gate rejects the alg/key mismatch before JOSE performs
      # signature math.
      key = gen_ec_key()
      jwk_map = public_map(key)
      signed = sign(key, base_header(jwk_map, %{"alg" => "ES256"}))
      forged = reheader(signed, base_header(jwk_map, %{"alg" => "RS256"}))

      assert {:error, :invalid_jwk} = DPoP.verify_proof(forged, verify_opts())
    end

    test "an RSA jwk presented under an EC header alg is :invalid_jwk" do
      key = gen_rsa_key()
      jwk_map = public_map(key)
      signed = sign(key, base_header(jwk_map, %{"alg" => "RS256"}))
      forged = reheader(signed, base_header(jwk_map, %{"alg" => "ES256"}))

      assert {:error, :invalid_jwk} = DPoP.verify_proof(forged, verify_opts())
    end

    test "a genuine, consistent RSA RS256 proof verifies (control)" do
      key = gen_rsa_key()
      jwk_map = public_map(key)
      proof = sign(key, base_header(jwk_map, %{"alg" => "RS256"}))

      assert {:ok, _result} = DPoP.verify_proof(proof, verify_opts())
    end
  end

  describe "an oct (symmetric) jwk is rejected" do
    test "oct jwk with an HS256 header is :invalid_alg (symmetric alg not whitelisted)" do
      # The natural shape: a symmetric key signs with HS256. RFC 9449 §4.2
      # forbids symmetric algorithms; Attesto's alg whitelist (asymmetric
      # only) rejects HS256 before the JWK is even consulted. This is the
      # earliest and cleanest rejection point.
      key = JOSE.JWK.from_oct(:crypto.strong_rand_bytes(32))
      {_, oct_map} = JOSE.JWK.to_map(key)
      proof = sign(key, %{"typ" => "dpop+jwt", "alg" => "HS256", "jwk" => oct_map})

      assert {:error, :invalid_alg} = DPoP.verify_proof(proof, verify_opts())
    end

    test "oct jwk smuggled under an asymmetric (ES256) header alg is :invalid_jwk" do
      # Forge the header to claim ES256 (which IS whitelisted) over a real
      # HS256 signature, keeping the oct jwk. The alg check passes, but the
      # oct JWK carries the `k` member, which Attesto treats as private-key
      # material (RFC 7518 §6.4 oct `k`), so extract_jwk/1 returns
      # :invalid_jwk before any signature math. A symmetric secret can never
      # be a valid DPoP proof key, and Attesto fails closed here.
      key = JOSE.JWK.from_oct(:crypto.strong_rand_bytes(32))
      {_, oct_map} = JOSE.JWK.to_map(key)
      signed = sign(key, %{"typ" => "dpop+jwt", "alg" => "HS256", "jwk" => oct_map})
      forged = reheader(signed, %{"typ" => "dpop+jwt", "alg" => "ES256", "jwk" => oct_map})

      assert {:error, :invalid_jwk} = DPoP.verify_proof(forged, verify_opts())
    end
  end
end
