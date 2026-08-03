defmodule Attesto.Parity.WalletParityTest do
  @moduledoc false
  # Wallet cross-language CONTRACT parity: Attesto issues each credential or
  # holder proof with a real P-256 key and a third-party JavaScript stack
  # verifies the wire artifact and recovers the same signed values.

  use ExUnit.Case, async: false

  alias __MODULE__.WalletKeystore
  alias Attesto.{CredentialProof, JWS, JwtVc, Mdoc, SdJwt, SdJwtVc, StatusList}
  alias Attesto.Test.NodeBridge

  @moduletag :parity

  @issuer "https://issuer.example"
  @vct "https://credentials.example/identity"

  case NodeBridge.availability() do
    :ok ->
      @moduletag node_ready: true

    {:skip, reason} ->
      @moduletag node_ready: false
      @moduletag skip: "Node wallet parity unavailable: #{reason}"
  end

  describe "SD-JWT VC parity" do
    test "Attesto issuance, disclosures, and KB-JWT verify in sd-jwt-js and jose",
         %{node_ready: ready} do
      if ready do
        issuer = keypair()
        holder = keypair()
        now = System.system_time(:second)
        nonce = "wallet-parity-nonce"
        audience = "https://verifier.example"

        issuance =
          SdJwtVc.issue([iss: @issuer, vct: @vct, pem: issuer.pem],
            claims: %{
              "birthdate" => "1990-01-02",
              "family_name" => "Doe",
              "given_name" => "Jane"
            },
            cnf: %{"jwk" => holder.public},
            iat: now,
            exp: now + 600
          )

        kb_claims = %{
          "aud" => audience,
          "iat" => now,
          "nonce" => nonce,
          "sd_hash" => sha256_b64url(issuance)
        }

        kb_jwt =
          JWS.sign_compact(
            holder.pem,
            %{"alg" => "ES256", "typ" => "kb+jwt"},
            kb_claims
          )

        presentation = issuance <> kb_jwt

        %{"claims" => js_claims, "header" => js_header, "keyBinding" => js_kb} =
          NodeBridge.call!("attesto_compat", :verifySdJwtVc, [
            presentation,
            issuer.public,
            nonce,
            audience,
            now
          ])

        assert {:ok, attesto} = SdJwtVc.verify(presentation, issuer.public, now: now)

        assert :ok =
                 SdJwt.verify_key_binding(attesto, holder.public,
                   nonce: nonce,
                   audience: audience,
                   now: now
                 )

        assert js_header["typ"] == "vc+sd-jwt"
        assert js_claims == attesto.claims
        assert js_kb == kb_claims

        %{"payload" => jose_kb} =
          NodeBridge.call!("attesto_compat", :verifyHolderProof, [
            kb_jwt,
            holder.public,
            "kb+jwt",
            kb_claims
          ])

        assert jose_kb == kb_claims
      end
    end

    test "an sd-jwt-js credential verifies in Attesto with identical claims",
         %{node_ready: ready} do
      if ready do
        issuer = keypair()
        now = System.system_time(:second)

        claims = %{
          "birthdate" => "1990-01-02",
          "family_name" => "Doe",
          "given_name" => "Jane",
          "iat" => now,
          "iss" => @issuer,
          "vct" => @vct
        }

        issuance =
          NodeBridge.call!("attesto_compat", :issueSdJwtVc, [
            claims,
            ["birthdate", "family_name", "given_name"],
            issuer.private
          ])

        assert {:ok, verified} = SdJwtVc.verify(issuance, issuer.public, now: now)
        assert verified.claims == claims
        assert verified.iss == @issuer
        assert verified.vct == @vct
      end
    end
  end

  describe "mdoc parity (Attesto -> @auth0/mdl)" do
    test "an IssuerSigned mdoc verifies and recovers the same namespaces",
         %{node_ready: ready} do
      if ready do
        issuer = keypair()
        holder = keypair()
        now = System.system_time(:second)
        doc_type = "org.iso.18013.5.1.mDL"

        namespaces = %{
          "org.iso.18013.5.1" => %{
            "age_over_21" => true,
            "birth_date" => "1990-01-02",
            "family_name" => "Doe",
            "given_name" => "Jane"
          },
          "org.iso.18013.5.1.aamva" => %{"organ_donor" => false}
        }

        assert {:ok, issued} =
                 Mdoc.issue(
                   device_key: holder.public,
                   doc_type: doc_type,
                   issuer_pem: issuer.pem,
                   namespaces: namespaces,
                   validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 3600}
                 )

        %{"docType" => js_doc_type, "namespaces" => js_namespaces} =
          NodeBridge.call!("attesto_compat", :verifyMdoc, [issued, issuer.public])

        assert {:ok, attesto} = Mdoc.verify(issued, issuer.public, now: now)
        assert js_doc_type == attesto.doc_type
        assert js_namespaces == attesto.namespaces
        assert js_doc_type == doc_type
        assert js_namespaces == namespaces
      end
    end
  end

  describe "jwt_vc_json parity (Attesto -> jose)" do
    test "a JWT VC verifies and returns the identical vc claim", %{node_ready: ready} do
      if ready do
        issuer = keypair()
        now = System.system_time(:second)

        jwt =
          JwtVc.issue([iss: @issuer, sub: "did:example:wallet", pem: issuer.pem],
            claims: %{
              "degree" => %{"name" => "BSc", "type" => "BachelorDegree"},
              "given_name" => "Jane"
            },
            type: ["VerifiableCredential", "UniversityDegreeCredential"],
            iat: now,
            nbf: now,
            exp: now + 600,
            jti: "https://issuer.example/credentials/degree-123"
          )

        %{"header" => js_header, "vc" => js_vc} =
          NodeBridge.call!("attesto_compat", :verifyJwtVc, [jwt, issuer.public])

        assert {:ok, attesto} =
                 JwtVc.verify(jwt, trusted_public(issuer), now: now, issuer: @issuer)

        assert js_header["typ"] == "JWT"
        assert js_vc == attesto.vc
        assert js_vc["credentialSubject"] == attesto.claims
      end
    end
  end

  describe "Token Status List parity (Attesto -> jose + zlib)" do
    test "a statuslist+jwt verifies and yields the same indexed status",
         %{node_ready: ready} do
      if ready do
        issuer = keypair()
        WalletKeystore.install(issuer.pem)
        now = System.system_time(:second)
        uri = "https://issuer.example/status/1"
        statuses = [0, 1, 2, 3, 1, 0, 3, 2, 1]
        index = 6

        token =
          StatusList.issue(WalletKeystore, uri, statuses,
            bits: 2,
            now: now,
            exp: now + 600
          )

        %{"bits" => js_bits, "header" => js_header, "status" => js_status, "sub" => js_sub} =
          NodeBridge.call!("attesto_compat", :verifyStatusList, [
            token,
            issuer.public,
            index
          ])

        assert {:ok, attesto} =
                 StatusList.verify(token, trusted_public(issuer), accepted_algs: ["ES256"])

        attesto_status = StatusList.status_at(attesto.statuses_binary, attesto.bits, index)
        assert js_header["typ"] == "statuslist+jwt"
        assert js_sub == attesto.sub
        assert js_bits == attesto.bits
        assert js_status == attesto_status
        assert js_status == Enum.at(statuses, index)
      end
    end
  end

  describe "OID4VCI holder proof parity (Attesto -> jose)" do
    test "an openid4vci-proof+jwt verifies with identical claims and holder key",
         %{node_ready: ready} do
      if ready do
        holder = keypair()
        now = System.system_time(:second)

        claims = %{
          "aud" => @issuer,
          "iat" => now,
          "iss" => "wallet-client",
          "nonce" => "credential-nonce"
        }

        proof =
          JWS.sign_compact(
            holder.pem,
            %{
              "alg" => "ES256",
              "jwk" => holder.public,
              "typ" => "openid4vci-proof+jwt"
            },
            claims
          )

        %{"header" => js_header, "payload" => js_claims} =
          NodeBridge.call!("attesto_compat", :verifyHolderProof, [
            proof,
            holder.public,
            "openid4vci-proof+jwt",
            claims
          ])

        assert {:ok, attesto} =
                 CredentialProof.verify_jwt(proof,
                   issuer: @issuer,
                   client_id: "wallet-client",
                   nonce: "credential-nonce",
                   now: now
                 )

        assert js_header["jwk"] == attesto.jwk
        assert js_claims == claims
        assert attesto.jkt == JOSE.JWK.thumbprint(holder.public)
      end
    end
  end

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_metadata, pem} = JOSE.JWK.to_pem(jwk)
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)
    {_metadata, private} = JOSE.JWK.to_map(jwk)
    %{pem: pem, private: private, public: public}
  end

  defp sha256_b64url(value) do
    value
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.url_encode64(padding: false)
  end

  defp trusted_public(keypair) do
    Map.merge(keypair.public, %{
      "alg" => "ES256",
      "kid" => Attesto.Key.kid(keypair.pem)
    })
  end

  defmodule WalletKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    def install(pem), do: Process.put({__MODULE__, :pem}, pem)

    @impl true
    def signing_pem, do: Process.get({__MODULE__, :pem})

    @impl true
    def verification_pems, do: [signing_pem()]
  end
end
