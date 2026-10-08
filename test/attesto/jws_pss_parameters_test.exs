defmodule Attesto.JWSPSSParametersTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.JWS

  @algorithms [{"PS256", :sha256, 32}, {"PS384", :sha384, 48}, {"PS512", :sha512, 64}]

  setup_all do
    private = JOSE.JWK.generate_key({:rsa, 2048})
    public = private |> JOSE.JWK.to_public_map() |> elem(1)
    %{private: private, public: public}
  end

  for {alg, hash, required_salt} <- @algorithms do
    test "#{alg} accepts only its RFC 7518 salt length", context do
      alg = unquote(alg)
      hash = unquote(hash)
      required_salt = unquote(required_salt)
      candidates = JWS.verification_candidates(context.public, alg: alg)
      claims = %{"sub" => "synthetic-subject"}

      for salt <- [0, 1, 31, 32, 33, 47, 48, 49, 63, 64, 65, 190] do
        token = signed(context.private, alg, hash, salt, hash, claims)

        # Independent OTP signing exercises genuine PSS encodings rather than
        # mutating a JOSE-generated token or relying on the library's signer.
        if salt == required_salt do
          assert {:ok, ^claims} = JWS.verify_strict(token, candidates)
        else
          assert {:error, :invalid_signature} = JWS.verify_strict(token, candidates)
        end
      end
    end

    test "#{alg} retains candidate ordering, caller errors and returned key", context do
      alg = unquote(alg)
      hash = unquote(hash)
      salt = unquote(required_salt)
      token = signed(context.private, alg, hash, salt, hash, %{"ok" => true})
      wrong = JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_public_map() |> elem(1)
      candidates = JWS.verification_candidates([wrong, context.public], alg: alg)
      successful = List.last(candidates)

      assert {:ok, %{"ok" => true}, ^successful} =
               JWS.verify_strict(token, candidates, return_key?: true, claims_map?: true)

      invalid = signed(context.private, alg, hash, 0, hash, %{"ok" => true})
      assert {:error, :denied} = JWS.verify_strict(invalid, candidates, terminal_error: :denied)
    end

    test "#{alg} rejects a different MGF1 hash and a different header algorithm", context do
      alg = unquote(alg)
      hash = unquote(hash)
      salt = unquote(required_salt)
      other_hash = unquote(if hash == :sha256, do: :sha384, else: :sha256)
      candidates = JWS.verification_candidates(context.public, alg: alg)
      token = signed(context.private, alg, hash, salt, other_hash, %{"ok" => true})
      assert {:error, :invalid_signature} = JWS.verify_strict(token, candidates)

      mismatched = signed(context.private, "RS256", hash, salt, hash, %{"ok" => true})
      assert {:error, :invalid_signature} = JWS.verify_strict(mismatched, candidates)
    end
  end

  test "PKCS1 and EC verification retain their existing behavior" do
    for {key, alg} <- [
          {JOSE.JWK.generate_key({:rsa, 2048}), "RS256"},
          {JOSE.JWK.generate_key({:ec, "P-256"}), "ES256"}
        ] do
      public = key |> JOSE.JWK.to_public_map() |> elem(1)
      candidates = JWS.verification_candidates(public, alg: alg)
      {_jws, token} = key |> JOSE.JWT.sign(%{"alg" => alg}, %{"ok" => true}) |> JOSE.JWS.compact()
      assert {:ok, %{"ok" => true}} = JWS.verify_strict(token, candidates)
    end
  end

  defp signed(private, alg, hash, salt, mgf_hash, claims) do
    header = %{"alg" => alg} |> JSON.encode!() |> JWS.encode64()
    payload = claims |> JSON.encode!() |> JWS.encode64()
    input = header <> "." <> payload
    key = private |> JOSE.JWK.to_key() |> elem(1)

    signature =
      :public_key.sign(input, hash, key,
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: salt,
        rsa_mgf1_md: mgf_hash
      )

    input <> "." <> JWS.encode64(signature)
  end
end
