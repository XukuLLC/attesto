defmodule Attesto.CredentialIssuerMetadataTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CredentialIssuerMetadata
  alias Attesto.JWS
  alias Attesto.Test.Factory

  @issuer "https://issuer.example.com"
  @credential_endpoint "https://issuer.example.com/credential"

  defp required_opts(configurations \\ %{"sd_jwt_vc" => %{"format" => "vc+sd-jwt", "vct" => "IdentityCredential"}}) do
    [
      credential_issuer: @issuer,
      credential_endpoint: @credential_endpoint,
      credential_configurations_supported: configurations
    ]
  end

  test "requires the issuer, endpoint, and a non-empty configuration map" do
    for opts <- [
          Keyword.delete(required_opts(), :credential_issuer),
          Keyword.delete(required_opts(), :credential_endpoint),
          Keyword.delete(required_opts(), :credential_configurations_supported),
          Keyword.put(required_opts(), :credential_configurations_supported, %{})
        ] do
      assert_raise ArgumentError, fn -> CredentialIssuerMetadata.build(opts) end
    end
  end

  test "returns the required fields with string keys" do
    metadata = CredentialIssuerMetadata.build(required_opts())

    assert metadata["credential_issuer"] == @issuer
    assert metadata["credential_endpoint"] == @credential_endpoint
    assert metadata["credential_configurations_supported"]["sd_jwt_vc"]["format"] == "vc+sd-jwt"
    assert Enum.all?(Map.keys(metadata), &is_binary/1)
  end

  test "drops nil values and ignores unknown options and configuration fields" do
    metadata =
      CredentialIssuerMetadata.build(
        required_opts(%{
          "config" => %{
            format: "jwt_vc_json",
            scope: nil,
            claims: nil,
            display: nil,
            ignored: "not advertised"
          }
        }) ++ [nonce_endpoint: nil, display: nil, unknown: "not advertised"]
      )

    configuration = metadata["credential_configurations_supported"]["config"]
    assert configuration == %{"format" => "jwt_vc_json"}
    refute Map.has_key?(metadata, "nonce_endpoint")
    refute Map.has_key?(metadata, "display")
    refute Map.has_key?(metadata, "unknown")
  end

  test "normalizes an SD-JWT VC configuration including jwt proof support" do
    configuration = %{
      format: "vc+sd-jwt",
      vct: "urn:example:identity",
      scope: "identity",
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: ["ES256"],
      proof_types_supported: %{
        "jwt" => %{"proof_signing_alg_values_supported" => ["ES256"]}
      }
    }

    actual =
      CredentialIssuerMetadata.build(required_opts(%{"identity" => configuration}))[
        "credential_configurations_supported"
      ]["identity"]

    assert actual == %{
             "format" => "vc+sd-jwt",
             "vct" => "urn:example:identity",
             "scope" => "identity",
             "cryptographic_binding_methods_supported" => ["jwk"],
             "credential_signing_alg_values_supported" => ["ES256"],
             "proof_types_supported" => %{
               "jwt" => %{"proof_signing_alg_values_supported" => ["ES256"]}
             }
           }
  end

  test "includes the optional top-level capability blocks" do
    display = [
      %{"name" => "Identity Credential", "locale" => "en-US", "logo" => %{"url" => "https://example.com/logo"}}
    ]

    metadata =
      CredentialIssuerMetadata.build(
        required_opts() ++
          [
            authorization_servers: ["https://auth.example.com"],
            nonce_endpoint: "https://issuer.example.com/nonce",
            deferred_credential_endpoint: "https://issuer.example.com/deferred",
            notification_endpoint: "https://issuer.example.com/notification",
            credential_response_encryption: %{
              alg_values_supported: ["ECDH-ES"],
              enc_values_supported: ["A256GCM"],
              encryption_required: true
            },
            batch_credential_issuance: %{batch_size: 10},
            display: display
          ]
      )

    assert metadata["authorization_servers"] == ["https://auth.example.com"]
    assert metadata["nonce_endpoint"] == "https://issuer.example.com/nonce"
    assert metadata["deferred_credential_endpoint"] == "https://issuer.example.com/deferred"
    assert metadata["notification_endpoint"] == "https://issuer.example.com/notification"

    assert metadata["credential_response_encryption"] == %{
             "alg_values_supported" => ["ECDH-ES"],
             "enc_values_supported" => ["A256GCM"],
             "encryption_required" => true
           }

    assert metadata["batch_credential_issuance"] == %{"batch_size" => 10}
    assert metadata["display"] == display
  end

  test "rejects a configuration missing format" do
    assert_raise ArgumentError, ~r/:format/, fn ->
      CredentialIssuerMetadata.build(required_opts(%{"bad" => %{}}))
    end
  end

  test "requires vct for vc+sd-jwt and dc+sd-jwt" do
    for format <- ["vc+sd-jwt", "dc+sd-jwt"] do
      assert_raise ArgumentError, ~r/:vct/, fn ->
        CredentialIssuerMetadata.build(required_opts(%{"bad" => %{format: format}}))
      end

      assert_raise ArgumentError, ~r/:vct/, fn ->
        CredentialIssuerMetadata.build(required_opts(%{"bad" => %{format: format, vct: 123}}))
      end
    end
  end

  test "requires format to be a non-empty string" do
    for format <- [nil, "", 123] do
      assert_raise ArgumentError, ~r/:format/, fn ->
        CredentialIssuerMetadata.build(required_opts(%{"bad" => %{format: format}}))
      end
    end
  end

  describe "signed/2" do
    test "produces a verifiable openidvci-issuer-metadata+jwt carrying the document" do
      pem = Factory.ec_pem()
      metadata = CredentialIssuerMetadata.build(required_opts())

      jwt = CredentialIssuerMetadata.signed(metadata, pem: pem, now: 1_700_000_000)

      assert {:ok, header} = JWS.peek_json(jwt, :protected)
      assert header["typ"] == "openidvci-issuer-metadata+jwt"
      assert header["alg"] == "ES256"
      # The public signing key travels in the header so a wallet can verify
      # without a separate key lookup, and the signature checks out against it.
      assert %{"kty" => "EC"} = header["jwk"]
      jwk = JOSE.JWK.from_map(header["jwk"])
      assert {true, _payload, _jws} = JOSE.JWS.verify_strict(jwk, ["ES256"], jwt)

      assert {:ok, claims} = JWS.peek_json(jwt, :payload)
      assert claims["iss"] == @issuer
      assert claims["sub"] == @issuer
      assert claims["iat"] == 1_700_000_000
      assert claims["credential_issuer"] == @issuer
      assert claims["credential_endpoint"] == @credential_endpoint
    end
  end
end
