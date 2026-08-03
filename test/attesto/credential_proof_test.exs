defmodule Attesto.CredentialProofTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CredentialProof

  @issuer "https://credential-issuer.example"
  @client_id "wallet-client"
  @nonce "credential-nonce"
  @now 1_800_000_000

  defp public_map(key) do
    {_, jwk_map} = JOSE.JWK.to_public_map(key)
    jwk_map
  end

  defp sign_proof(key, jwk_map, claim_overrides \\ %{}) do
    header = %{
      "alg" => "ES256",
      "jwk" => jwk_map,
      "typ" => "openid4vci-proof+jwt"
    }

    claims =
      Map.merge(
        %{
          "aud" => @issuer,
          "iat" => @now,
          "iss" => @client_id,
          "nonce" => @nonce
        },
        claim_overrides
      )

    {_, proof} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    proof
  end

  defp verify_opts do
    [issuer: @issuer, client_id: @client_id, nonce: @nonce, now: @now]
  end

  test "verifies a valid proof and returns the public JWK and its thumbprint" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    jwk_map = public_map(key)
    proof = sign_proof(key, jwk_map)

    assert {:ok, %{jwk: ^jwk_map, jkt: jkt}} = CredentialProof.verify_jwt(proof, verify_opts())
    assert jkt == JOSE.JWK.thumbprint(key)
  end

  test "rejects a proof header containing private-key material" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    jwk_map = public_map(key) |> Map.put("d", "private")
    proof = sign_proof(key, jwk_map)

    assert {:error, :invalid_jwk} = CredentialProof.verify_jwt(proof, verify_opts())
  end

  test "rejects a proof signed by the wrong embedded key" do
    signer = JOSE.JWK.generate_key({:ec, "P-256"})
    embedded = JOSE.JWK.generate_key({:ec, "P-256"})
    proof = sign_proof(signer, public_map(embedded))

    assert {:error, :invalid_signature} = CredentialProof.verify_jwt(proof, verify_opts())
  end

  test "keeps the 300-second age and 60-second future-skew boundaries" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    jwk_map = public_map(key)

    for {offset, expected} <- [
          {-300, :ok},
          {-301, :error},
          {60, :ok},
          {61, :error}
        ] do
      proof = sign_proof(key, jwk_map, %{"iat" => @now + offset})

      case {expected, CredentialProof.verify_jwt(proof, verify_opts())} do
        {:ok, {:ok, _}} -> :ok
        {:error, {:error, :invalid_iat}} -> :ok
        _ -> flunk("unexpected result at iat offset #{offset}")
      end
    end
  end

  describe "optional key_attestation cross-check" do
    defp key_attestation_jwt(signer, attested_keys, overrides \\ %{}) do
      header = %{"alg" => "ES256", "typ" => "key-attestation+jwt", "kid" => "ks-1"}

      claims =
        Map.merge(
          %{
            "iat" => @now,
            "exp" => @now + 300,
            "nonce" => @nonce,
            "attested_keys" => attested_keys
          },
          overrides
        )

      {_header, compact} = signer |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
      compact
    end

    defp trusted_key_attestation_signer(signer), do: %{"keys" => [Map.put(public_map(signer), "kid", "ks-1")]}

    test "is a no-op by default, even when the proof carries a key_attestation header" do
      holder = JOSE.JWK.generate_key({:ec, "P-256"})
      signer = JOSE.JWK.generate_key({:ec, "P-256"})
      holder_map = public_map(holder)

      attestation = key_attestation_jwt(signer, [holder_map])

      header = %{
        "alg" => "ES256",
        "jwk" => holder_map,
        "typ" => "openid4vci-proof+jwt",
        "key_attestation" => attestation
      }

      claims = %{"aud" => @issuer, "iat" => @now, "iss" => @client_id, "nonce" => @nonce}
      {_header, proof} = holder |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      assert {:ok, %{key_attestation: nil}} = CredentialProof.verify_jwt(proof, verify_opts())
    end

    test "verifies a key_attestation header and returns it when the trusted keys opt is supplied" do
      holder = JOSE.JWK.generate_key({:ec, "P-256"})
      signer = JOSE.JWK.generate_key({:ec, "P-256"})
      holder_map = public_map(holder)

      attestation = key_attestation_jwt(signer, [holder_map])

      header = %{
        "alg" => "ES256",
        "jwk" => holder_map,
        "typ" => "openid4vci-proof+jwt",
        "key_attestation" => attestation
      }

      claims = %{"aud" => @issuer, "iat" => @now, "iss" => @client_id, "nonce" => @nonce}
      {_header, proof} = holder |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      opts = Keyword.put(verify_opts(), :key_attestation_trusted_jwks, trusted_key_attestation_signer(signer))

      assert {:ok, %{key_attestation: %{attested_keys: [^holder_map]}}} = CredentialProof.verify_jwt(proof, opts)
    end

    test "rejects a proof whose key is not among the key attestation's attested_keys" do
      holder = JOSE.JWK.generate_key({:ec, "P-256"})
      other = JOSE.JWK.generate_key({:ec, "P-256"})
      signer = JOSE.JWK.generate_key({:ec, "P-256"})
      holder_map = public_map(holder)

      # attests a DIFFERENT key than the one the proof is signed with
      attestation = key_attestation_jwt(signer, [public_map(other)])

      header = %{
        "alg" => "ES256",
        "jwk" => holder_map,
        "typ" => "openid4vci-proof+jwt",
        "key_attestation" => attestation
      }

      claims = %{"aud" => @issuer, "iat" => @now, "iss" => @client_id, "nonce" => @nonce}
      {_header, proof} = holder |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      opts = Keyword.put(verify_opts(), :key_attestation_trusted_jwks, trusted_key_attestation_signer(signer))

      assert {:error, :key_not_attested} = CredentialProof.verify_jwt(proof, opts)
    end

    test "rejects a key attestation not signed by a trusted key" do
      holder = JOSE.JWK.generate_key({:ec, "P-256"})
      signer = JOSE.JWK.generate_key({:ec, "P-256"})
      impostor = JOSE.JWK.generate_key({:ec, "P-256"})
      holder_map = public_map(holder)

      attestation = key_attestation_jwt(impostor, [holder_map])

      header = %{
        "alg" => "ES256",
        "jwk" => holder_map,
        "typ" => "openid4vci-proof+jwt",
        "key_attestation" => attestation
      }

      claims = %{"aud" => @issuer, "iat" => @now, "iss" => @client_id, "nonce" => @nonce}
      {_header, proof} = holder |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()

      opts = Keyword.put(verify_opts(), :key_attestation_trusted_jwks, trusted_key_attestation_signer(signer))

      assert {:error, :invalid_key_attestation} = CredentialProof.verify_jwt(proof, opts)
    end

    test "require_key_attestation: true rejects a proof with no key_attestation header" do
      holder = JOSE.JWK.generate_key({:ec, "P-256"})
      signer = JOSE.JWK.generate_key({:ec, "P-256"})
      holder_map = public_map(holder)
      proof = sign_proof(holder, holder_map)

      opts =
        verify_opts()
        |> Keyword.put(:key_attestation_trusted_jwks, trusted_key_attestation_signer(signer))
        |> Keyword.put(:require_key_attestation, true)

      assert {:error, :missing_key_attestation} = CredentialProof.verify_jwt(proof, opts)
    end
  end
end
