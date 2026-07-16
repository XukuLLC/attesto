defmodule Attesto.Parity.CrossLanguageParityTest do
  @moduledoc false
  # Cross-language CONTRACT parity: prove that artifacts Attesto produces
  # (and accepts) are bit-compatible with a reference Python stack
  # (joserfc + cryptography). This is an IN-PROCESS check: the `erlang_python`
  # `:py` NIF evaluates the Python directly inside the BEAM, with no live
  # HTTP endpoint involved. The three legs:
  #
  #   1. JWT verify: an Attesto-minted RS256 JWT verifies and decodes to
  #      the same claims under joserfc AND under a raw `cryptography`
  #      verifier (a second, decode-independent implementation), using the
  #      public PEM Attesto derives from the signing key.
  #   2. Thumbprint: the RFC 7638 JWK thumbprint Attesto computes for an
  #      EC P-256 key equals joserfc's thumbprint over the same JWK.
  #   3. DPoP proof: a DPoP proof JWS built entirely by Python (joserfc,
  #      ES256) verifies in Attesto.DPoP.verify_proof, and the verified
  #      `jkt` equals Python's own thumbprint of the signing key. This
  #      proves a real third-party Python client interoperates with the
  #      engine's proof verifier.
  #
  # The reference helpers live in `test/support/python/attesto_compat.py`,
  # driven through `Attesto.Test.PythonBridge`. The module self-skips when
  # the bridge runtime or the required Python packages are unavailable,
  # rather than failing the suite.

  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Test.PythonBridge

  @moduletag :parity

  # test/parity/cross_language_parity_test.exs -> test/support/python
  @python_lib_path Path.expand("../support/python", __DIR__)

  setup_all do
    case PythonBridge.availability() do
      :ok -> %{python: :ready}
      {:skip, reason} -> %{python: {:skip, reason}}
    end
  end

  setup %{python: python} do
    case python do
      :ready -> :ok
      {:skip, reason} -> {:ok, skip: "python parity stack unavailable: #{reason}"}
    end
  end

  describe "JWT verify parity (Attesto RS256 -> joserfc + cryptography)" do
    test "an Attesto-minted token decodes to identical claims in both Python verifiers", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      public_pem = Attesto.Key.public_pem(pem)

      {:ok, token} =
        Attesto.Token.mint(config, %{
          kind: "client",
          sub: "oc_live_parity",
          scopes: ["documents.read", "documents.write"],
          claims: %{"client_id" => "oc_live_parity"}
        })

      # joserfc leg.
      jose_claims =
        py_eval!("joserfc_verify_rs256(token, public_pem)", %{
          "public_pem" => public_pem,
          "token" => token.access_token
        })

      assert jose_claims["sub"] == "oc_live_parity"
      assert jose_claims["iss"] == "https://api.example.com/"
      assert jose_claims["scope"] == "documents.read documents.write"

      # cryptography leg: a decode-independent verifier enforcing iss/aud.
      crypto_claims =
        py_eval!("cryptography_verify_rs256(token, public_pem, issuer, audience)", %{
          "audience" => "https://api.example.com/",
          "issuer" => "https://api.example.com/",
          "public_pem" => public_pem,
          "token" => token.access_token
        })

      assert crypto_claims["sub"] == "oc_live_parity"
      assert crypto_claims["iss"] == "https://api.example.com/"
      assert crypto_claims["scope"] == "documents.read documents.write"

      # Both Python verifiers agree with each other and with Attesto's own
      # verifier on the load-bearing claims.
      {:ok, attesto_claims} = Attesto.Token.verify(config, token.access_token)

      for key <- ["sub", "iss", "scope"] do
        assert jose_claims[key] == crypto_claims[key]
        assert jose_claims[key] == attesto_claims[key]
      end
    end
  end

  describe "ID Token verify parity (Attesto RS256 -> joserfc + cryptography)" do
    test "an Attesto-minted ID Token decodes to identical claims in both Python verifiers", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      public_pem = Attesto.Key.public_pem(pem)
      client_id = "client-parity"

      # at_hash is computed over this access token (OIDC Core §3.1.3.6); the
      # canonical OIDC example yields "77QmUPtjPfzWtF2AnpK9RQ".
      access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"

      {:ok, id_token} =
        Attesto.IDToken.mint(config, "usr_parity", client_id,
          nonce: "n-parity",
          access_token: access_token
        )

      # joserfc leg: a generic RS256 JWT verifier, so it accepts the ID
      # Token's `typ: "JWT"` header (it would equally accept `at+jwt`; the
      # typ distinction is enforced Elixir-side, not by the RS256 verifier).
      jose_claims =
        py_eval!("joserfc_verify_rs256(token, public_pem)", %{
          "public_pem" => public_pem,
          "token" => id_token
        })

      assert jose_claims["sub"] == "usr_parity"
      assert jose_claims["iss"] == "https://api.example.com/"
      # aud is the OAuth client_id, NOT the RFC 9068 resource audience.
      assert jose_claims["aud"] == client_id
      assert jose_claims["nonce"] == "n-parity"
      assert jose_claims["at_hash"] == "77QmUPtjPfzWtF2AnpK9RQ"
      refute Map.has_key?(jose_claims, "scope")

      # cryptography leg: a decode-independent RS256 verifier. Here the
      # "audience" it enforces is the client_id, since for an ID Token that
      # is the audience (OIDC Core §2).
      crypto_claims =
        py_eval!("cryptography_verify_rs256(token, public_pem, issuer, audience)", %{
          "audience" => client_id,
          "issuer" => "https://api.example.com/",
          "public_pem" => public_pem,
          "token" => id_token
        })

      assert crypto_claims["sub"] == "usr_parity"
      assert crypto_claims["aud"] == client_id

      # Both Python verifiers agree with each other and with Attesto's own
      # ID-Token verifier on the load-bearing claims.
      {:ok, attesto_claims} = Attesto.IDToken.verify(config, id_token, client_id: client_id, nonce: "n-parity")

      for key <- ["sub", "iss", "aud", "nonce", "at_hash"] do
        assert jose_claims[key] == crypto_claims[key]
        assert jose_claims[key] == attesto_claims[key]
      end
    end
  end

  describe "ID Token c_hash parity (Attesto RS256 -> joserfc + cryptography)" do
    test "Attesto's c_hash matches an independent Python computation over the same code", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      public_pem = Attesto.Key.public_pem(pem)
      client_id = "client-parity"

      # c_hash is computed over the authorization code (OIDC Core §3.3.2.11)
      # with the SAME construction as at_hash: SHA-256 the ASCII octets, take
      # the left-most 16 bytes, base64url without padding (RS256 -> SHA-256).
      code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"

      {:ok, id_token} =
        Attesto.IDToken.mint(config, "usr_parity", client_id,
          nonce: "n-parity",
          code: code
        )

      # The minted token must carry a c_hash (and, since we passed no
      # access_token, no at_hash) - read it back through joserfc so the
      # claim we compare against is the one a third-party stack would see.
      jose_claims =
        py_eval!("joserfc_verify_rs256(token, public_pem)", %{
          "public_pem" => public_pem,
          "token" => id_token
        })

      minted_c_hash = jose_claims["c_hash"]
      assert is_binary(minted_c_hash)
      refute Map.has_key?(jose_claims, "at_hash")

      # Independently recompute the c_hash in Python from the raw code,
      # reusing attesto_compat's RFC-7638-grade base64url-no-pad and the
      # bytes->str boundary helper but NONE of Attesto's hashing code: this
      # is a genuine cross-implementation check of the §3.3.2.11 hash
      # construction, not a round-trip of one library's canonicalisation.
      python_c_hash =
        py_eval_with_module!(
          "m._b64url_nopad(__import__('hashlib').sha256(m._s(code).encode('ascii')).digest()[:16])",
          code
        )

      assert python_c_hash == minted_c_hash

      # And Attesto's own verifier accepts the token and returns the same
      # claim, so all three implementations agree on the c_hash bytes.
      {:ok, attesto_claims} =
        Attesto.IDToken.verify(config, id_token, client_id: client_id, nonce: "n-parity")

      assert attesto_claims["c_hash"] == minted_c_hash
      assert attesto_claims["c_hash"] == python_c_hash
    end
  end

  describe "ID Token multi-audience parity (Attesto verify -> joserfc + cryptography)" do
    test "an aud array with azp decodes identically in both Python verifiers and Attesto", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      public_pem = Attesto.Key.public_pem(pem)
      client_id = "client-a"

      # The minter always sets aud to a single client_id, so this exercises
      # the array branch of the OIDC §3.1.3.7-item-3 audience check with a
      # token hand-signed by the same keystore key. azp names the client
      # the token is FOR, which OIDC Core §2 REQUIRES when aud carries more
      # than one value - the canonical multi-audience ID Token shape.
      id_token =
        signed_id_token(config, %{
          "sub" => "usr_parity",
          "aud" => [client_id, "client-b"],
          "azp" => client_id
        })

      # joserfc leg: a generic RS256 verifier accepts the array aud and
      # returns it verbatim, so the Python view of the audience matches the
      # wire bytes.
      jose_claims =
        py_eval!("joserfc_verify_rs256(token, public_pem)", %{
          "public_pem" => public_pem,
          "token" => id_token
        })

      assert jose_claims["aud"] == [client_id, "client-b"]
      assert jose_claims["azp"] == client_id

      # cryptography leg: the decode-independent verifier enforces that
      # `audience` is PRESENT IN the aud array (its membership branch, not a
      # scalar equality), proving the second implementation treats the array
      # the same way.
      crypto_claims =
        py_eval!("cryptography_verify_rs256(token, public_pem, issuer, audience)", %{
          "audience" => client_id,
          "issuer" => "https://api.example.com/",
          "public_pem" => public_pem,
          "token" => id_token
        })

      assert crypto_claims["aud"] == [client_id, "client-b"]
      assert crypto_claims["azp"] == client_id

      # Attesto's own verifier accepts the token for client-a (present in the
      # array, azp matching) and returns the same multi-valued audience: all
      # three agree on multi-aud + azp semantics.
      {:ok, attesto_claims} = Attesto.IDToken.verify(config, id_token, client_id: client_id)

      assert attesto_claims["aud"] == [client_id, "client-b"]
      assert attesto_claims["azp"] == client_id

      for key <- ["aud", "azp", "sub", "iss"] do
        assert jose_claims[key] == crypto_claims[key]
        assert jose_claims[key] == attesto_claims[key]
      end
    end
  end

  describe "ID Token inbound parity (Python RS256 issuer -> Attesto verifier)" do
    test "a Python-signed ID Token verifies in Attesto", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      now = System.system_time(:second)
      client_id = "client-python"

      claims = %{
        "iss" => config.issuer,
        "sub" => "usr_python",
        "aud" => client_id,
        "iat" => now,
        "exp" => now + 3600,
        "nonce" => "n-python"
      }

      id_token =
        py_eval!("build_rs256_jwt(claims, private_pem)", %{
          "claims" => claims,
          "private_pem" => pem
        })

      assert {:ok, verified} =
               Attesto.IDToken.verify(config, id_token,
                 client_id: client_id,
                 nonce: "n-python",
                 now: now
               )

      assert verified["sub"] == "usr_python"
      assert verified["aud"] == client_id
      assert verified["nonce"] == "n-python"
    end

    test "a Python-signed access-token typ is rejected as an ID Token", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      now = System.system_time(:second)
      client_id = "client-python"

      claims = %{
        "iss" => config.issuer,
        "sub" => "usr_python",
        "aud" => client_id,
        "iat" => now,
        "exp" => now + 3600
      }

      id_token =
        py_eval!("build_rs256_jwt(claims, private_pem, typ)", %{
          "claims" => claims,
          "private_pem" => pem,
          "typ" => "at+jwt"
        })

      assert {:error, :unexpected_typ} =
               Attesto.IDToken.verify(config, id_token, client_id: client_id, now: now)
    end
  end

  describe "resource-audience parity (Python joserfc issuer -> Attesto verifier)" do
    test "Python-signed scalar and array audiences obey the explicit trust policy", _ctx do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      now = System.system_time(:second)
      resource_a = "https://resource.example/a"
      resource_b = "https://resource.example/b"

      base_claims = %{
        "iss" => config.issuer,
        "sub" => "oc_python_resource",
        "iat" => now,
        "exp" => now + 3600,
        "jti" => "python-resource-token",
        "scope" => "documents.read",
        "principal_kind" => "client",
        "typ" => "access",
        "client_id" => "oc_python_resource"
      }

      scalar =
        py_eval!("build_rs256_jwt(claims, private_pem, typ)", %{
          "claims" => Map.put(base_claims, "aud", resource_a),
          "private_pem" => pem,
          "typ" => "at+jwt"
        })

      assert {:error, :invalid_audience} = Attesto.Token.verify(config, scalar, now: now)

      assert {:ok, %{"aud" => ^resource_a}} =
               Attesto.Token.verify(config, scalar,
                 now: now,
                 trusted_audiences: [resource_a]
               )

      multiple =
        py_eval!("build_rs256_jwt(claims, private_pem, typ)", %{
          "claims" => Map.put(base_claims, "aud", [resource_a, resource_b]),
          "private_pem" => pem,
          "typ" => "at+jwt"
        })

      assert {:ok, %{"aud" => [^resource_a, ^resource_b]}} =
               Attesto.Token.verify(config, multiple,
                 now: now,
                 trusted_audiences: [resource_a, resource_b]
               )

      assert {:error, :invalid_audience} =
               Attesto.Token.verify(config, multiple,
                 now: now,
                 trusted_audiences: [resource_a]
               )
    end
  end

  describe "thumbprint parity (Attesto compute_jkt -> joserfc RFC 7638)" do
    test "an EC P-256 JWK yields the same RFC 7638 thumbprint in both stacks", _ctx do
      # Elixir is the source of the key here: generate a real EC P-256 key
      # and export its public JWK members, so both stacks thumbprint the
      # SAME jwk. (The DPoP-proof leg below exercises the Python -> Attesto
      # direction over a JWK embedded in a compact JWS, the real interop
      # path.)
      {_, public_jwk} = JOSE.JWK.to_public_map(JOSE.JWK.generate_key({:ec, "P-256"}))

      attesto_jkt = Attesto.DPoP.compute_jkt(public_jwk)
      python_jkt = py_eval!("joserfc_jwk_thumbprint(jwk)", %{"jwk" => public_jwk})

      assert Attesto.Thumbprint.valid?(attesto_jkt)
      assert attesto_jkt == python_jkt
    end
  end

  describe "DPoP proof parity (Python joserfc client -> Attesto verifier)" do
    test "a Python-built ES256 DPoP proof verifies in Attesto with the matching jkt", _ctx do
      htu = "https://api.example.com/oauth/token"
      iat = System.system_time(:second)
      jti = "parity-#{System.unique_integer([:positive])}"

      {proof, _public_jwk, python_jkt} =
        py_eval!("build_es256_dpop_proof(htm, htu, iat, jti)", %{
          "htm" => "POST",
          "htu" => htu,
          "iat" => iat,
          "jti" => jti
        })

      assert {:ok, verified} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "POST",
                 http_uri: htu,
                 now: iat
               )

      # The verified thumbprint Attesto returns is exactly the RFC 7638
      # thumbprint Python computed over the same signing key.
      assert verified.jkt == python_jkt
      assert verified.htm == "POST"
      assert verified.htu == htu
      assert verified.jti == jti
      assert verified.iat == iat
    end
  end

  # Evaluate `attesto_compat.<expr>` through the bridge with the module
  # directory on sys.path, decoding the result back to Elixir terms.
  defp py_eval!(expr, bindings) do
    PythonBridge.eval_wrapped!("__import__('attesto_compat').#{expr}", bindings, paths: [@python_lib_path])
  end

  # Recompute the OIDC §3.3.2.11 c_hash for `code` in Python, composing the
  # `attesto_compat` module's `_s` (bytes->str) and `_b64url_nopad` helpers
  # with stdlib hashlib - none of Attesto's own hashing code - for a genuine
  # cross-implementation check. `m` (the module) and `code` are bound as
  # lambda parameters rather than left as free names, so the references
  # resolve in the lambda's own scope instead of relying on the eval frame's
  # locals leaking into a nested scope.
  defp py_eval_with_module!(expr, code) do
    PythonBridge.eval_wrapped!(
      "(lambda m, code: #{expr})(__import__('attesto_compat'), code)",
      %{"code" => code},
      paths: [@python_lib_path]
    )
  end

  # Sign an arbitrary ID-token claim set with the configured keystore key and
  # the exact JOSE header `Attesto.IDToken` emits (`alg: RS256`, the keystore
  # `kid`, `typ: JWT`), so verify/3's array/azp branches can be exercised with
  # multi-audience shapes the minter does not itself produce. Mirrors the
  # `signed_id_token/2` helper in `test/attesto/id_token_test.exs`.
  defp signed_id_token(config, overrides) do
    now = System.system_time(:second)
    pem = config.keystore.signing_pem()
    jwk = Attesto.Key.signing_jwk(pem)

    claims =
      %{
        "iss" => config.issuer,
        "sub" => "usr_parity",
        "aud" => "client-a",
        "iat" => now,
        "exp" => now + 3600
      }
      |> Map.merge(overrides)

    header = %{"alg" => "RS256", "kid" => Attesto.Key.kid(pem), "typ" => "JWT"}
    {_, jwt} = jwk |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end
end
