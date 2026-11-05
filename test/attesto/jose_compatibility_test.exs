defmodule Attesto.JOSECompatibilityTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Test.JWT

  setup do
    original_json_module = JOSE.json_module()
    :ok = JOSE.json_module(:jose_json_otp)
    on_exit(fn -> JOSE.json_module(original_json_module) end)
  end

  test "EC keys export and import through a public JWK before ES256 verification" do
    private_key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_map} = JOSE.JWK.to_public_map(private_key)
    public_key = JOSE.JWK.from_map(public_map)
    payload = ~s({"sub":"minimum-version-consumer"})

    {_, compact} =
      private_key
      |> JOSE.JWS.sign(payload, %{"alg" => "ES256", "typ" => "JWT"})
      |> JOSE.JWS.compact()

    assert %{"crv" => "P-256", "kty" => "EC", "x" => _x, "y" => _y} = public_map
    refute Map.has_key?(public_map, "d")
    assert {true, ^payload, _verified_jws} = JOSE.JWS.verify_strict(public_key, ["ES256"], compact)
  end

  test "the builtin OTP JSON backend encodes an Elixir nil JWT claim as null" do
    private_key = JOSE.JWK.generate_key({:ec, "P-256"})

    {_, compact} =
      private_key
      |> JOSE.JWT.sign(%{"alg" => "ES256"}, %{"optional" => nil, "sub" => "json-consumer"})
      |> JOSE.JWS.compact()

    [_header, encoded_payload, _signature] = String.split(compact, ".")
    payload = encoded_payload |> Base.url_decode64!(padding: false) |> JSON.decode!()

    assert payload == %{"optional" => nil, "sub" => "json-consumer"}
  end

  # JOSE decodes a verified payload with its configured JSON backend, and the
  # backends disagree on JSON null: the builtin OTP backend yields :null, Jason
  # and Poison yield nil. Attesto's confirmation checks have to refuse a
  # present "cnf": null under every backend, not only the default one.
  for backend <- [:jose_json_otp, :jose_json_jason] do
    test "JWS.verify_strict/3 returns JSON null as nil at every depth under #{backend}" do
      :ok = JOSE.json_module(unquote(backend))
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      claims = %{"top" => nil, "nested" => %{"inner" => nil, "list" => [nil, 1]}, "sub" => "x"}

      jwt = JWT.sign_compact(jwk, %{"alg" => "ES256"}, claims)

      assert {:ok, ^claims} = Attesto.JWS.verify_strict(jwt, [{nil, "ES256", JOSE.JWK.to_public(jwk)}])
    end

    test "Token.verify/3 refuses an explicit null cnf under #{backend}" do
      :ok = JOSE.json_module(unquote(backend))
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      now = System.os_time(:second)

      claims = %{
        "aud" => "https://api.example.com/",
        "client_id" => "oc_abc123",
        "exp" => now + 3600,
        "iat" => now,
        "iss" => "https://api.example.com/",
        "jti" => "jti-#{System.unique_integer([:positive])}",
        "principal_kind" => "client",
        "scope" => "documents.read",
        "sub" => "oc_abc123",
        "typ" => "access"
      }

      sign = fn claims ->
        JWT.sign_compact(
          Attesto.Key.signing_jwk(pem),
          %{"alg" => Attesto.Token.signing_alg(), "kid" => Attesto.Key.kid(pem)},
          claims
        )
      end

      assert {:error, :unsupported_confirmation} = Attesto.Token.verify(config, sign.(Map.put(claims, "cnf", nil)))
      assert {:ok, verified} = Attesto.Token.verify(config, sign.(claims))
      refute Map.has_key?(verified, "cnf")
    end

    test "JwtVc.verify/3 refuses an explicit null cnf under #{backend}" do
      :ok = JOSE.json_module(unquote(backend))
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {_metadata, public} = JOSE.JWK.to_public_map(jwk)
      kid = JOSE.JWK.thumbprint(jwk)
      jwks = %{"keys" => [Map.merge(public, %{"alg" => "ES256", "kid" => kid, "use" => "sig"})]}
      now = 1_700_000_000

      claims = %{
        "iss" => "https://issuer.example",
        "sub" => "did:example:holder",
        "nbf" => now,
        "exp" => now + 600,
        "iat" => now,
        "jti" => "urn:uuid:6e09bcb4-5955-4a08-9a54-14f0833bd951",
        "vc" => %{
          "@context" => ["https://www.w3.org/2018/credentials/v1"],
          "type" => ["VerifiableCredential"],
          "credentialSubject" => %{"degree" => "BSc"},
          "issuer" => "https://issuer.example"
        }
      }

      sign = fn claims ->
        JWT.sign_compact(jwk, %{"alg" => "ES256", "kid" => kid, "typ" => "JWT"}, claims)
      end

      assert {:error, :invalid_cnf} = claims |> Map.put("cnf", nil) |> sign.() |> Attesto.JwtVc.verify(jwks, now: now)
      assert {:ok, %{cnf: nil}} = claims |> sign.() |> Attesto.JwtVc.verify(jwks, now: now)
    end
  end
end
