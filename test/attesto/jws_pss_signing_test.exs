defmodule Attesto.JWSPSSSigningTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.JWS
  alias Attesto.Test.DPoP, as: TestDPoP

  @algorithms [{"PS256", :sha256, 32}, {"PS384", :sha384, 48}, {"PS512", :sha512, 64}]

  setup_all do
    private = JOSE.JWK.generate_key({:rsa, 2048})
    public = private |> JOSE.JWK.to_public() |> JOSE.JWK.to_key() |> elem(1)
    %{private: private, public: public}
  end

  for {alg, hash, salt} <- @algorithms do
    test "#{alg} JWK signing pins its salt and MGF1 hash", context do
      header = %{"alg" => unquote(alg), "typ" => "example+jwt", "kid" => "example-key", "custom" => ["value"]}
      claims = %{"sub" => "synthetic-subject", "unicode" => "café"}
      compact = JWS.sign_compact_jwk(context.private, header, claims)

      assert {:ok, ^header} = JWS.peek_json(compact, :protected)
      assert {:ok, ^claims} = JWS.peek_json(compact, :payload)
      assert_parameters(compact, context.public, unquote(hash), unquote(salt))
    end

    test "#{alg} DPoP fixture signing pins its salt and MGF1 hash", context do
      compact = TestDPoP.proof(context.private, "GET", "https://resource.example", alg: unquote(alg))
      assert_parameters(compact, context.public, unquote(hash), unquote(salt))

      assert {:ok, _proof} =
               Attesto.DPoP.verify_proof(compact, http_method: "GET", http_uri: "https://resource.example")
    end

    test "#{alg} refuses non-RSA signing keys" do
      for key <- [JOSE.JWK.generate_key({:ec, "P-256"}), JOSE.JWK.generate_key({:oct, 32})] do
        assert_raise ArgumentError, "PSS signing requires an RSA private key", fn ->
          JWS.sign_compact_jwk(key, %{"alg" => unquote(alg)}, %{"sub" => "synthetic-subject"})
        end
      end
    end
  end

  defp assert_parameters(compact, public, hash, salt) do
    [protected, payload, encoded_signature] = String.split(compact, ".")
    signature = Base.url_decode64!(encoded_signature, padding: false)
    input = protected <> "." <> payload

    options = [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: salt, rsa_mgf1_md: hash]
    assert :public_key.verify(input, hash, signature, public, options)
    refute :public_key.verify(input, hash, signature, public, Keyword.put(options, :rsa_pss_saltlen, salt - 1))

    other_hash = if hash == :sha256, do: :sha384, else: :sha256
    refute :public_key.verify(input, hash, signature, public, Keyword.put(options, :rsa_mgf1_md, other_hash))
  end
end
