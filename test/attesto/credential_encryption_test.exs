defmodule Attesto.CredentialEncryptionTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{CredentialEncryption, JWE, Key}
  alias Attesto.Test.Factory

  defmodule EncKeystore do
    @pem Factory.ec_pem()
    def signing_pem, do: @pem
    def verification_pems, do: [@pem]
  end

  defmodule RotatingEncKeystore do
    @current_pem Factory.ec_pem()
    @old_pem Factory.ec_pem()
    def signing_pem, do: @current_pem
    def verification_pems, do: [@current_pem, @old_pem]
  end

  defmodule RsaKeystore do
    @pem Factory.rsa_pem()
    def signing_pem, do: @pem
    def verification_pems, do: [@pem]
  end

  defp wallet_jwk(opts \\ []) do
    private = JOSE.JWK.generate_key({:ec, "P-256"})
    {_kty, public} = JOSE.JWK.to_public_map(private)

    public =
      public
      |> Map.merge(%{"alg" => "ECDH-ES", "use" => "enc"})
      |> maybe_put_kid(Keyword.get(opts, :kid))

    {private, public}
  end

  defp maybe_put_kid(map, nil), do: map
  defp maybe_put_kid(map, kid), do: Map.put(map, "kid", kid)

  test "builds OID4VCI request and response encryption metadata with distinct kids" do
    req_meta = CredentialEncryption.request_metadata(RotatingEncKeystore)
    resp_meta = CredentialEncryption.response_metadata(encryption_required: true)

    keys = req_meta["jwks"]["keys"]
    assert length(keys) == 2
    assert Enum.all?(keys, &(is_binary(&1["kid"]) and &1["alg"] == "ECDH-ES" and &1["use"] == "enc"))
    assert length(Enum.uniq_by(keys, & &1["kid"])) == 2
    assert req_meta["enc_values_supported"] == ["A256GCM", "A128GCM"]
    assert req_meta["encryption_required"] == false

    assert resp_meta == %{
             "alg_values_supported" => ["ECDH-ES"],
             "enc_values_supported" => ["A256GCM", "A128GCM"],
             "zip_values_supported" => ["DEF"],
             "encryption_required" => true
           }

    assert_raise ArgumentError, ~r/EC P-256/, fn ->
      CredentialEncryption.request_metadata(RsaKeystore)
    end
  end

  test "decrypt_request decrypts compact JWE with active or rotated keystore key" do
    req_meta = CredentialEncryption.request_metadata(RotatingEncKeystore)
    [current_pub, old_pub] = req_meta["jwks"]["keys"]
    payload = %{"credential_configuration_id" => "pid", "proof" => %{"proof_type" => "jwt", "jwt" => "abc"}}

    for target_pub <- [current_pub, old_pub] do
      header = %{"alg" => "ECDH-ES", "enc" => "A256GCM", "cty" => "json", "kid" => target_pub["kid"]}
      assert {:ok, compact} = JWE.encrypt(target_pub, JSON.encode!(payload), header)
      assert {:ok, ^payload} = CredentialEncryption.decrypt_request(compact, RotatingEncKeystore)
    end
  end

  test "decrypt_request rejects unknown kid, missing kid, invalid cty, and non-object payload" do
    [pub] = CredentialEncryption.request_metadata(EncKeystore)["jwks"]["keys"]

    {:ok, unknown_kid} =
      JWE.encrypt(pub, ~s({"a":1}), %{"alg" => "ECDH-ES", "enc" => "A256GCM", "cty" => "json", "kid" => "nope"})

    assert {:error, :invalid_encryption_parameters} =
             CredentialEncryption.decrypt_request(unknown_kid, EncKeystore)

    {:ok, no_kid} =
      JWE.encrypt(pub, ~s({"a":1}), %{"alg" => "ECDH-ES", "enc" => "A256GCM", "cty" => "json"})

    assert {:error, :invalid_encryption_parameters} =
             CredentialEncryption.decrypt_request(no_kid, EncKeystore)

    {:ok, bad_cty} =
      JWE.encrypt(pub, ~s({"a":1}), %{
        "alg" => "ECDH-ES",
        "enc" => "A256GCM",
        "cty" => "text/plain",
        "kid" => pub["kid"]
      })

    assert {:error, :invalid_encryption_parameters} =
             CredentialEncryption.decrypt_request(bad_cty, EncKeystore)

    {:ok, json_array} =
      JWE.encrypt(pub, "[1,2]", %{"alg" => "ECDH-ES", "enc" => "A256GCM", "cty" => "json", "kid" => pub["kid"]})

    assert {:error, :invalid_credential_request} =
             CredentialEncryption.decrypt_request(json_array, EncKeystore)

    assert Key.kid(EncKeystore.signing_pem()) == pub["kid"]
  end

  test "encrypt_response round-trips with wallet key (with and without kid) and rejects invalid params" do
    {private, public_with_kid} = wallet_jwk(kid: "wallet-enc-1")
    {_private2, public_no_kid} = wallet_jwk()
    response_body = %{"credentials" => [%{"credential" => "eyJ..."}]}

    {:ok, compact_with_kid} =
      CredentialEncryption.encrypt_response(response_body, %{
        "jwk" => public_with_kid,
        "enc" => "A256GCM"
      })

    assert {:ok, plaintext, header} = JWE.decrypt(private, compact_with_kid)
    assert header["kid"] == "wallet-enc-1"
    assert header["cty"] == "json"
    assert header["enc"] == "A256GCM"
    assert JSON.decode!(plaintext) == response_body

    {:ok, compact_no_kid} =
      CredentialEncryption.encrypt_response(response_body, %{
        "jwk" => public_no_kid,
        "enc" => "A128GCM"
      })

    assert {:ok, _header} = JWE.peek_protected_header(compact_no_kid)
    refute Map.has_key?(elem(JWE.peek_protected_header(compact_no_kid), 1), "kid")

    # Unsupported algorithms/compression and private recipient material
    {_kty, private_map} = JOSE.JWK.to_map(private)

    for bad <- [
          %{"jwk" => Map.put(public_with_kid, "alg", "RSA-OAEP"), "enc" => "A256GCM"},
          %{"jwk" => public_with_kid, "enc" => "A192GCM"},
          %{"jwk" => public_with_kid, "enc" => "A256GCM", "zip" => "ZLIB"},
          %{"jwk" => Map.put(private_map, "alg", "ECDH-ES"), "enc" => "A256GCM"},
          %{"jwk" => Map.put(public_with_kid, "y", Base.url_encode64(<<0::256>>, padding: false)), "enc" => "A256GCM"}
        ] do
      assert {:error, :invalid_encryption_parameters} =
               CredentialEncryption.encrypt_response(response_body, bad)
    end
  end

  test "parse_deferred_request validates transaction_id and optional credential_response_encryption" do
    {_priv, pub} = wallet_jwk(kid: "k1")

    assert {:ok, %{transaction_id: "tx-1", response_encryption: nil}} =
             CredentialEncryption.parse_deferred_request(%{"transaction_id" => "tx-1"})

    assert {:ok, %{transaction_id: "tx-1", response_encryption: %{"jwk" => ^pub, "enc" => "A256GCM"}}} =
             CredentialEncryption.parse_deferred_request(%{
               "transaction_id" => "tx-1",
               "credential_response_encryption" => %{"jwk" => pub, "enc" => "A256GCM"}
             })

    assert {:error, :missing_transaction_id} = CredentialEncryption.parse_deferred_request(%{})

    assert {:error, :invalid_credential_response_encryption} =
             CredentialEncryption.parse_deferred_request(%{
               "transaction_id" => "tx-1",
               "credential_response_encryption" => %{"enc" => "A256GCM"}
             })
  end

  test "compresses only requested outbound responses and continues to refuse compressed inbound requests" do
    {private, public} = wallet_jwk(kid: "wallet-enc")
    response = %{"credentials" => [%{"credential" => String.duplicate("credential", 1000)}]}

    assert {:ok, compact} =
             CredentialEncryption.encrypt_response(response, %{"jwk" => public, "enc" => "A256GCM", "zip" => "DEF"})

    assert {:ok, header} = JWE.peek_protected_header(compact)
    assert header["zip"] == "DEF"
    assert header["kid"] == "wallet-enc"
    [_, _, _, ciphertext, _] = String.split(compact, ".")
    assert byte_size(Base.url_decode64!(ciphertext, padding: false)) < byte_size(JSON.encode!(response))
    {plaintext, _jwe} = JOSE.JWE.block_decrypt(private, compact)
    assert JSON.decode!(plaintext) == response
    assert {:error, :invalid_header} = JWE.decrypt(private, compact)

    assert {:error, :invalid_encryption_parameters} =
             CredentialEncryption.encrypt_response(
               response,
               %{"jwk" => public, "enc" => "A256GCM", "zip" => "DEF"},
               max_plaintext_bytes: 100
             )

    [recipient] = CredentialEncryption.request_metadata(EncKeystore)["jwks"]["keys"]

    {_modules, compressed_request} =
      JOSE.JWE.block_encrypt(
        {JOSE.JWK.from_map(recipient), JOSE.JWK.generate_key({:ec, "P-256"})},
        ~s({"credential_configuration_id":"pid"}),
        %{
          "alg" => "ECDH-ES",
          "enc" => "A256GCM",
          "kid" => recipient["kid"],
          "zip" => "DEF",
          "cty" => "json"
        }
      )
      |> JOSE.JWE.compact()

    assert {:error, :invalid_encryption_parameters} =
             CredentialEncryption.decrypt_request(compressed_request, EncKeystore)

    refute Map.has_key?(CredentialEncryption.request_metadata(EncKeystore), "zip_values_supported")
    assert CredentialEncryption.response_metadata()["zip_values_supported"] == ["DEF"]
  end
end
