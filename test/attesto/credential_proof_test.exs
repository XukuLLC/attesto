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
end
