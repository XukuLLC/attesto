defmodule Attesto.ConformanceVectorsTest do
  @moduledoc false
  # Pins attesto's crypto + canonicalization (base64url-no-pad SHA-256,
  # RFC 7638 JWK thumbprinting, the RS256 JWS stack) against PUBLISHED
  # RFC test vectors. Every value below is copied verbatim from the cited
  # RFC, so a base64url / canonicalization regression is caught against an
  # external source of truth, not against a token attesto minted itself.
  #
  # All assertions here are pure functions of fixed inputs (no Config, no
  # app env, no named singleton store), so this module is async-safe.
  use ExUnit.Case, async: true

  alias Attesto.DPoP
  alias Attesto.PKCE
  alias Attesto.Thumbprint
  alias Attesto.Token

  # ===================================================================
  # (1) RFC 7638 Section 3.1 - JWK Thumbprint worked example.
  #
  #     https://www.rfc-editor.org/rfc/rfc7638#section-3.1
  #
  # The RSA public JWK in that section has the published SHA-256
  # thumbprint below. attesto computes `jkt` from a DPoP proof's embedded
  # JWK the same way, so this is THE canonical vector for compute_jkt/1:
  # it transitively validates the JSON member ordering, the UTF-8
  # canonicalization, the SHA-256, and the base64url-no-pad encoding.
  # ===================================================================

  # Verbatim from RFC 7638 Section 3.1.
  @rfc7638_jwk %{
    "kty" => "RSA",
    "n" =>
      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" <>
        "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn" <>
        "64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz" <>
        "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08" <>
        "qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1" <>
        "jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e" => "AQAB"
  }

  # Verbatim from RFC 7638 Section 3.1.
  @rfc7638_thumbprint "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

  describe "RFC 7638 Section 3.1 JWK thumbprint" do
    test "compute_jkt/1 of the RFC 7638 example JWK equals the published thumbprint" do
      assert DPoP.compute_jkt(@rfc7638_jwk) == @rfc7638_thumbprint
    end

    test "the RFC 7638 thumbprint is a canonical 43-char base64url-no-pad value" do
      assert byte_size(@rfc7638_thumbprint) == 43
      assert Thumbprint.valid?(@rfc7638_thumbprint)
    end
  end

  # ===================================================================
  # (2) RFC 7636 Appendix B - PKCE S256 worked example.
  #
  #     https://www.rfc-editor.org/rfc/rfc7636#appendix-B
  #
  # code_challenge = base64url(SHA-256(code_verifier)), no padding.
  # Pinned here as a conformance vector in addition to pkce_test.exs so a
  # regression in the shared SHA-256/base64url path shows up against the
  # external RFC value regardless of which suite runs.
  # ===================================================================

  # Verbatim from RFC 7636 Appendix B.
  @rfc7636_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @rfc7636_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  describe "RFC 7636 Appendix B PKCE S256 vector" do
    test "PKCE.challenge/1 of the RFC verifier equals the published challenge" do
      assert {:ok, @rfc7636_challenge} = PKCE.challenge(@rfc7636_verifier)
    end

    test "PKCE.verify/3 accepts the RFC verifier against the RFC challenge" do
      assert :ok = PKCE.verify(@rfc7636_challenge, @rfc7636_verifier, "S256")
    end

    test "the RFC 7636 challenge is a canonical 43-char base64url thumbprint shape" do
      assert byte_size(@rfc7636_challenge) == 43
      assert PKCE.valid_challenge?(@rfc7636_challenge)
    end
  end

  # ===================================================================
  # (3) RFC 9449 Section 7.1 - DPoP `ath` worked example.
  #
  #     https://www.rfc-editor.org/rfc/rfc9449#section-7.1
  #
  # The protected-resource example pairs a concrete access token with the
  # `ath` claim carried in the accompanying DPoP proof, where
  # ath = base64url(SHA-256(ASCII(access_token))), no padding. This is a
  # real published vector for compute_ath/1.
  # ===================================================================

  # Verbatim from RFC 9449 Section 7.1 (the `Authorization: DPoP <token>`
  # value and the decoded `ath` claim of the proof in that same example).
  @rfc9449_access_token "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
  @rfc9449_ath "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"

  describe "RFC 9449 Section 7.1 DPoP ath vector" do
    test "compute_ath/1 of the RFC 9449 example access token equals the published ath" do
      assert DPoP.compute_ath(@rfc9449_access_token) == @rfc9449_ath
    end

    # Secondary pin: a hand-computed base64url(SHA-256("...")) over a fixed
    # ASCII string, independent of any RFC, so the base64url-no-pad path is
    # nailed down even if the RFC vector above were ever (wrongly) edited.
    # Computed with:
    #   printf '%s' "RFC9449-conformance-fixed-access-token" \
    #     | openssl dgst -sha256 -binary | openssl base64 -A \
    #     | tr '+/' '-_' | tr -d '='
    @fixed_access_token "RFC9449-conformance-fixed-access-token"
    @fixed_ath "3m-T57wRcczi_dREy3QH5Mzxs7z-9SoCxFgbagcVrrw"

    test "compute_ath/1 matches a hand-computed base64url SHA-256 of a fixed string" do
      assert DPoP.compute_ath(@fixed_access_token) == @fixed_ath
    end

    test "compute_ath/1 agrees with Thumbprint.of/1 on the RFC token" do
      # compute_ath is documented as base64url(SHA-256(token)); cross-check
      # it against the shared primitive that produces jkt and PKCE values.
      assert DPoP.compute_ath(@rfc9449_access_token) == Thumbprint.of(@rfc9449_access_token)
    end

    test "the RFC 9449 ath is a canonical 43-char base64url-no-pad value" do
      assert byte_size(@rfc9449_ath) == 43
      assert Thumbprint.valid?(@rfc9449_ath)
    end
  end

  # ===================================================================
  # (4) RFC 7515 Appendix A.2 - RS256 JWS worked example.
  #
  #     https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2
  #
  # Validates the underlying RS256 stack attesto signs and verifies with:
  # the exact compact JWS from the RFC must verify under the exact RSA
  # public key from the RFC, using JOSE directly (the same library
  # Attesto.Token rides). This pins the RS256 verify path against an
  # external vector rather than against an attesto-minted token.
  # ===================================================================

  # JWS Protected Header from RFC 7515 Appendix A.2: {"alg":"RS256"}
  # Complete JWS compact serialization, verbatim from Appendix A.2 (the
  # display line breaks in the RFC are removed to form the wire string).
  @rfc7515_jws "eyJhbGciOiJSUzI1NiJ9" <>
                 ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" <>
                 "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" <>
                 ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" <>
                 "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" <>
                 "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" <>
                 "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" <>
                 "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" <>
                 "p0igcN_IoypGlUPQGe77Rw"

  # RSA public key from RFC 7515 Appendix A.2, verbatim "n" and "e".
  @rfc7515_public_jwk %{
    "kty" => "RSA",
    "n" =>
      "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp" <>
        "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW" <>
        "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs" <>
        "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9" <>
        "kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk" <>
        "2PAcDTW9gb54h4FRWyuXpoQ",
    "e" => "AQAB"
  }

  describe "RFC 7515 Appendix A.2 RS256 JWS vector" do
    test "the RFC 7515 compact JWS verifies under the RFC's RSA public key" do
      jwk = JOSE.JWK.from_map(@rfc7515_public_jwk)

      # Pin the algorithm explicitly: verify_strict rejects any alg other
      # than RS256, as Attesto.Token does for a key resolved to RS256.
      assert {true, %JOSE.JWT{}, %JOSE.JWS{}} =
               JOSE.JWT.verify_strict(jwk, ["RS256"], @rfc7515_jws)
    end

    test "the RFC 7515 protected header carries alg RS256, matching Token.signing_alg/0" do
      protected = JOSE.JWS.peek_protected(@rfc7515_jws)
      assert {:ok, %{"alg" => "RS256"}} = JSON.decode(protected)
      assert Token.signing_alg() == "RS256"
    end

    test "a tampered RFC 7515 JWS does not verify (negative control)" do
      jwk = JOSE.JWK.from_map(@rfc7515_public_jwk)
      # Flip the final signature character; the signature must no longer
      # verify, proving the positive result above is not vacuous.
      tampered = String.slice(@rfc7515_jws, 0..-2//1) <> flip_last_char(@rfc7515_jws)

      assert {false, %JOSE.JWT{}, %JOSE.JWS{}} =
               JOSE.JWT.verify_strict(jwk, ["RS256"], tampered)
    end
  end

  defp flip_last_char(s) do
    case String.last(s) do
      "A" -> "B"
      _ -> "A"
    end
  end
end
