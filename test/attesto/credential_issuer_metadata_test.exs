defmodule Attesto.CredentialIssuerMetadataTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CredentialIssuerMetadata
  alias Attesto.JWS
  alias Attesto.Test.Factory

  @issuer "https://issuer.example.com"
  @credential_endpoint "https://issuer.example.com/credential"

  defmodule RotatingKeystore do
    def signing_pem do
      Process.put({__MODULE__, :reads}, Process.get({__MODULE__, :reads}, 0) + 1)
      Factory.ec_pem()
    end
  end

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

  test "current credential metadata survives JSON and signed serialization for SD-JWT and mdoc" do
    for {format, type_fields, path} <- [
          {"dc+sd-jwt", %{vct: "urn:example:identity"}, ["given_name"]},
          {"mso_mdoc", %{doctype: "eu.europa.ec.eudi.pid.1"}, ["eu.europa.ec.eudi.pid.1", "given_name"]}
        ] do
      credential_metadata = %{
        "https://example.com/metadata-extension" => %{"enabled" => true, "value" => nil},
        display: [
          %{
            name: "Identity Credential",
            locale: "en-US",
            description: "Identity information",
            logo: %{uri: "data:image/svg+xml;base64,PHN2Zy8+", alt_text: "Credential logo"},
            background_image: %{uri: "https://issuer.example.com/background.png"},
            background_color: "#12107c",
            text_color: "#FFFFFF"
          },
          %{name: "本人確認", locale: "ja-JP"}
        ],
        claims: [
          %{path: path, mandatory: true, display: [%{name: "Given Name", locale: "en-US"}]},
          %{path: List.replace_at(path, -1, "family_name"), mandatory: false}
        ]
      }

      configuration = Map.merge(type_fields, %{format: format, credential_metadata: credential_metadata})
      metadata = CredentialIssuerMetadata.build(required_opts(%{"identity" => configuration}))
      actual = metadata["credential_configurations_supported"]["identity"]
      expected = credential_metadata |> JSON.encode!() |> JSON.decode!()
      assert actual["credential_metadata"] == expected
      refute Map.has_key?(actual, "claims")
      refute Map.has_key?(actual, "display")
      assert JSON.decode!(JSON.encode!(metadata))["credential_configurations_supported"]["identity"] == actual

      jwt = CredentialIssuerMetadata.signed(metadata, pem: Factory.ec_pem())
      assert {:ok, signed} = JWS.peek_json(jwt, :payload)
      assert signed["credential_configurations_supported"]["identity"]["credential_metadata"] == expected
    end
  end

  test "claim paths keep array selectors and original display order" do
    paths = [["address"], ["address", "street_address"], ["jobs", nil, "title"], ["scores", 0], ["scores", 1]]
    claims = Enum.map(paths, &%{"path" => &1})
    configuration = %{format: "dc+sd-jwt", vct: "urn:example:identity", credential_metadata: %{"claims" => claims}}
    metadata = CredentialIssuerMetadata.build(required_opts(%{"identity" => configuration}))
    assert metadata["credential_configurations_supported"]["identity"]["credential_metadata"]["claims"] == claims
  end

  test "legacy configuration claims and display remain unchanged alongside current metadata" do
    legacy_claims = %{"given_name" => %{"display" => [%{"name" => "Given name"}]}}
    legacy_display = [%{"name" => "Legacy identity"}]

    configuration = %{
      format: "dc+sd-jwt",
      vct: "urn:example:identity",
      claims: legacy_claims,
      display: legacy_display,
      credential_metadata: %{claims: [%{path: ["family_name"]}]}
    }

    metadata = CredentialIssuerMetadata.build(required_opts(%{"identity" => configuration}))
    actual = metadata["credential_configurations_supported"]["identity"]
    assert actual["claims"] == legacy_claims
    assert actual["display"] == legacy_display
    assert actual["credential_metadata"] == %{"claims" => [%{"path" => ["family_name"]}]}
  end

  test "rejects malformed current credential metadata and claim descriptions" do
    for credential_metadata <- [
          [],
          "unexpected",
          1,
          %{claims: nil},
          %{claims: []},
          %{claims: %{}},
          %{claims: ["given_name"]},
          %{claims: [%{}]},
          %{claims: [%{path: []}]},
          %{claims: [%{path: "given_name"}]},
          %{claims: [%{path: [false]}]},
          %{claims: [%{path: ["given_name", -1]}]},
          %{claims: [%{path: ["given_name"], mandatory: "true"}]},
          %{claims: [%{path: ["given_name"], display: []}]},
          %{claims: [%{path: ["given_name"], display: [%{locale: 1}]}]},
          %{claims: [%{path: ["given_name"], display: [%{locale: "en-US"}, %{locale: "EN-us"}]}]},
          %{"claims" => [%{"path" => ["given_name"]}], :claims => [%{path: ["family_name"]}]},
          %{"extension" => {:not, :json}},
          %{display: [%{name: <<255>>}]}
        ] do
      assert_raise ArgumentError, ~r/:credential_metadata/, fn ->
        CredentialIssuerMetadata.build(
          required_opts(%{
            "identity" => %{format: "dc+sd-jwt", vct: "urn:example:identity", credential_metadata: credential_metadata}
          })
        )
      end
    end
  end

  test "rejects invalid credential display properties" do
    for display <- [
          [],
          nil,
          %{},
          [false],
          [%{}],
          [%{name: nil}],
          [%{name: "Identity", locale: false}],
          [%{name: "Identity", logo: "unexpected"}],
          [%{name: "Identity", logo: %{}}],
          [%{name: "Identity", logo: %{uri: 1}}],
          [%{name: "Identity", logo: %{uri: "relative/path"}}],
          [%{name: "Identity", logo: %{uri: "https://example.com", alt_text: false}}],
          [%{name: "Identity", background_image: %{}}],
          [%{name: "Identity", background_color: 1}],
          [%{name: "Identity", locale: "en-US"}, %{name: "Identity", locale: "EN-us"}]
        ] do
      assert_raise ArgumentError, ~r/:credential_metadata/, fn ->
        CredentialIssuerMetadata.build(
          required_opts(%{
            "identity" => %{format: "dc+sd-jwt", vct: "urn:example:identity", credential_metadata: %{display: display}}
          })
        )
      end
    end
  end

  test "mdoc claim paths require namespace and data-element string components" do
    for path <- [["given_name"], [nil, "given_name"], ["namespace", 0], ["namespace", "given_name", false]] do
      assert_raise ArgumentError, ~r/:credential_metadata/, fn ->
        CredentialIssuerMetadata.build(
          required_opts(%{
            "mdoc" => %{
              format: "mso_mdoc",
              doctype: "eu.europa.ec.eudi.pid.1",
              credential_metadata: %{claims: [%{path: path}]}
            }
          })
        )
      end
    end
  end

  test "repeated or contradictory claim paths are rejected" do
    for paths <- [
          [["given_name"], ["given_name"]],
          [["jobs", nil, "title"], ["jobs", 0, "title"]],
          [["jobs", 0, "title"], ["jobs", nil, "title"]],
          [["address", "street"], ["address", 0]],
          [["address", nil], ["address", "street"]]
        ] do
      assert_raise ArgumentError, ~r/repeated or contradictory/, fn ->
        CredentialIssuerMetadata.build(
          required_opts(%{
            "identity" => %{
              format: "dc+sd-jwt",
              vct: "urn:example:identity",
              credential_metadata: %{claims: Enum.map(paths, &%{path: &1})}
            }
          })
        )
      end
    end
  end

  test "mdoc metadata retains its document type and numeric COSE signing algorithms" do
    configuration = %{
      "format" => "mso_mdoc",
      "doctype" => "eu.europa.ec.eudi.pid.1",
      "scope" => "eu.europa.ec.eudi.pid.mdoc",
      "cryptographic_binding_methods_supported" => ["cose_key"],
      "credential_signing_alg_values_supported" => [-7, -9],
      "proof_types_supported" => %{"jwt" => %{"proof_signing_alg_values_supported" => ["ES256"]}}
    }

    metadata = CredentialIssuerMetadata.build(required_opts(%{"mdoc" => configuration}))
    assert metadata["credential_configurations_supported"]["mdoc"] == configuration
    assert JSON.decode!(JSON.encode!(metadata))["credential_configurations_supported"]["mdoc"] == configuration
  end

  test "mdoc document type is required and must be a valid non-empty string" do
    for doctype <- [nil, "", " \t", 123, [], <<255>>] do
      assert_raise ArgumentError, ~r/:doctype/, fn ->
        CredentialIssuerMetadata.build(required_opts(%{"mdoc" => %{format: "mso_mdoc", doctype: doctype}}))
      end
    end
  end

  test "mdoc signing algorithms reject JOSE names and noninteger COSE identifiers" do
    for algorithms <- [["ES256"], [-7, "ES256"], [-7.0], [nil], [true], -7, %{}] do
      assert_raise ArgumentError, ~r/list of COSE integers/, fn ->
        CredentialIssuerMetadata.build(
          required_opts(%{
            "mdoc" => %{
              format: "mso_mdoc",
              doctype: "org.iso.18013.5.1.mDL",
              credential_signing_alg_values_supported: algorithms
            }
          })
        )
      end
    end
  end

  test "JWT credential formats retain string-only signing algorithms" do
    for format <- ["vc+sd-jwt", "dc+sd-jwt", "jwt_vc_json", "jwt_vc_json-ld"] do
      configuration = %{
        format: format,
        vct: "urn:example:identity",
        credential_signing_alg_values_supported: ["ES256"],
        doctype: 123
      }

      metadata = CredentialIssuerMetadata.build(required_opts(%{"jwt" => configuration}))
      actual = metadata["credential_configurations_supported"]["jwt"]
      assert actual["credential_signing_alg_values_supported"] == ["ES256"]
      refute Map.has_key?(actual, "doctype")

      assert_raise ArgumentError, ~r/list of strings/, fn ->
        CredentialIssuerMetadata.build(
          required_opts(%{"jwt" => %{configuration | credential_signing_alg_values_supported: [-7]}})
        )
      end
    end
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
    test "keystore metadata embeds the same inferred kid as its protected header" do
      metadata = CredentialIssuerMetadata.build(required_opts())
      jwt = CredentialIssuerMetadata.signed(metadata, keystore: RotatingKeystore, now: 1_700_000_000)

      assert Process.get({RotatingKeystore, :reads}) == 1
      assert {:ok, %{"kid" => kid, "jwk" => %{"kid" => kid} = jwk}} = JWS.peek_json(jwt, :protected)
      assert {:ok, ^kid} = Attesto.Thumbprint.of_jwk(jwk)

      candidates = JWS.verification_candidates(%{"keys" => [jwk]}, kid: kid, accepted_algs: ["ES256"])
      assert [{^kid, "ES256", _key}] = candidates
      assert {:ok, %{"credential_issuer" => @issuer}} = JWS.verify_strict(jwt, candidates)
      refute Map.has_key?(jwk, "d")
    end

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
