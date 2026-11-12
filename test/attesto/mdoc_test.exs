defmodule Attesto.MdocTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{Cose, Mdoc, Thumbprint}
  alias Attesto.Test.{CoseFixture, X509Fixture}

  @doc_type "org.iso.18013.5.1.mDL"
  @mdl_namespace "org.iso.18013.5.1"
  @aamva_namespace "org.iso.18013.5.1.aamva"

  setup do
    {issuer_pem, issuer_public} = keypair()
    {_holder_pem, holder_public} = keypair()
    now = System.system_time(:second)

    opts =
      issue_opts(issuer_pem, holder_public, now,
        namespaces: %{
          @mdl_namespace => %{
            "age_over_21" => true,
            "birth_date" => "1990-01-02",
            "family_name" => "Doe",
            "given_name" => "Jane"
          },
          @aamva_namespace => %{"organ_donor" => false}
        }
      )

    %{holder_public: holder_public, issuer_pem: issuer_pem, issuer_public: issuer_public, now: now, opts: opts}
  end

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp issue_opts(issuer_pem, holder_public, now, overrides) do
    defaults = [
      device_key: holder_public,
      doc_type: @doc_type,
      issuer_pem: issuer_pem,
      namespaces: %{@mdl_namespace => %{"family_name" => "Doe"}},
      validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 3600}
    ]

    Keyword.merge(defaults, overrides)
  end

  defp decode!(encoded) do
    assert {:ok, value, ""} = CBOR.decode(encoded)
    value
  end

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  test "issue/1 and verify/3 recover every element and the holder key", ctx do
    assert {:ok, issued} = Mdoc.issue(ctx.opts)

    assert {:ok, verified} = Mdoc.verify(issued, ctx.issuer_public, now: ctx.now)
    assert verified.doc_type == @doc_type
    assert verified.device_key == ctx.holder_public
    assert verified.validity == Keyword.fetch!(ctx.opts, :validity)

    assert verified.namespaces == %{
             @mdl_namespace => %{
               "age_over_21" => true,
               "birth_date" => "1990-01-02",
               "family_name" => "Doe",
               "given_name" => "Jane"
             },
             @aamva_namespace => %{"organ_donor" => false}
           }
  end

  test "rejects oversized base64url input before decoding it", ctx do
    encoded = String.duplicate("A", 1_398_103)
    assert {:error, :invalid_mdoc} = Mdoc.verify(encoded, ctx.issuer_public, now: ctx.now)
  end

  test "a changed element value fails item-digest verification", ctx do
    assert {:ok, issued} = Mdoc.issue(ctx.opts)
    raw = Base.url_decode64!(issued, padding: false)
    issuer_signed = decode!(raw)
    [first_item | remaining_items] = issuer_signed["nameSpaces"][@mdl_namespace]
    %CBOR.Tag{tag: 24, value: encoded_item_value} = first_item
    %CBOR.Tag{tag: :bytes, value: encoded_item} = encoded_item_value
    item = decode!(encoded_item)

    changed_item =
      %CBOR.Tag{
        tag: 24,
        value: bytes(CBOR.encode(Map.put(item, "elementValue", "tampered")))
      }

    tampered =
      put_in(
        issuer_signed,
        ["nameSpaces", @mdl_namespace],
        [changed_item | remaining_items]
      )

    assert {:error, :digest_mismatch} = Mdoc.verify(CBOR.encode(tampered), ctx.issuer_public, now: ctx.now)
  end

  test "expired and not-yet-valid documents are rejected", ctx do
    expired_opts =
      Keyword.put(ctx.opts, :validity, %{
        signed: ctx.now - 7200,
        valid_from: ctx.now - 7100,
        valid_until: ctx.now - 3600
      })

    future_opts =
      Keyword.put(ctx.opts, :validity, %{
        signed: ctx.now,
        valid_from: ctx.now + 3600,
        valid_until: ctx.now + 7200
      })

    assert {:ok, expired} = Mdoc.issue(expired_opts)
    assert {:ok, future} = Mdoc.issue(future_opts)
    assert {:error, :expired} = Mdoc.verify(expired, ctx.issuer_public, now: ctx.now)
    assert {:error, :not_yet_valid} = Mdoc.verify(future, ctx.issuer_public, now: ctx.now)
  end

  test "issuance rejects invalid MSO timestamp ordering", ctx do
    for validity <- invalid_validities(ctx.now) do
      assert {:error, :invalid_options} = Mdoc.issue(Keyword.put(ctx.opts, :validity, validity))
    end
  end

  test "verification rejects correctly signed MSOs with invalid timestamp ordering", ctx do
    assert {:ok, issued} = Mdoc.issue(ctx.opts)

    for validity <- invalid_validities(ctx.now) do
      issuer_signed = issued |> Base.url_decode64!(padding: false) |> decode!()
      {:ok, mso_payload} = Cose.verify1(CBOR.encode(issuer_signed["issuerAuth"]), ctx.issuer_public, [])
      %CBOR.Tag{tag: 24, value: %CBOR.Tag{tag: :bytes, value: encoded_mso}} = decode!(mso_payload)
      mso = decode!(encoded_mso)

      validity_info = %{
        "signed" => datetime(validity.signed),
        "validFrom" => datetime(validity.valid_from),
        "validUntil" => datetime(validity.valid_until)
      }

      changed_payload =
        %CBOR.Tag{
          tag: 24,
          value: bytes(CBOR.encode(Map.put(mso, "validityInfo", validity_info)))
        }
        |> CBOR.encode()

      changed_issuer_auth = Cose.sign1(ctx.issuer_pem, changed_payload, [])
      assert {:ok, ^changed_payload} = Cose.verify1(changed_issuer_auth, ctx.issuer_public, [])

      nonconforming =
        issuer_signed
        |> Map.put("issuerAuth", decode!(changed_issuer_auth))
        |> CBOR.encode()

      assert {:error, :invalid_mdoc} = Mdoc.verify(nonconforming, ctx.issuer_public, now: ctx.now)
    end
  end

  test "a validity period beginning at the signing time remains valid", ctx do
    validity = %{signed: ctx.now, valid_from: ctx.now, valid_until: ctx.now + 3600}
    assert {:ok, issued} = Mdoc.issue(Keyword.put(ctx.opts, :validity, validity))
    assert {:ok, verified} = Mdoc.verify(issued, ctx.issuer_public, now: ctx.now)
    assert verified.validity == validity
  end

  defp invalid_validities(now) do
    [
      %{signed: now + 1, valid_from: now, valid_until: now + 3600},
      %{signed: now - 10, valid_from: now, valid_until: now},
      %{signed: now - 10, valid_from: now + 1, valid_until: now}
    ]
  end

  defp datetime(unix_seconds) do
    %CBOR.Tag{tag: 0, value: unix_seconds |> DateTime.from_unix!(:second) |> DateTime.to_iso8601()}
  end

  test "expected_doc_type rejects a different document type", ctx do
    assert {:ok, issued} = Mdoc.issue(ctx.opts)

    assert {:error, :unexpected_doc_type} =
             Mdoc.verify(issued, ctx.issuer_public,
               expected_doc_type: "eu.europa.ec.eudi.pid.1",
               now: ctx.now
             )
  end

  test "x5chain is carried in issuerAuth while supplied-key verification still succeeds", ctx do
    chain = [<<48, 3, 2, 1, 1>>, <<48, 3, 2, 1, 2>>]
    opts = Keyword.put(ctx.opts, :x5chain, chain)

    assert {:ok, issued} = Mdoc.issue(opts)
    assert {:ok, _verified} = Mdoc.verify(issued, ctx.issuer_public, now: ctx.now)

    issuer_signed = issued |> Base.url_decode64!(padding: false) |> decode!()
    [_protected, unprotected, _payload, _signature] = issuer_signed["issuerAuth"]

    assert Enum.map(unprotected[33], fn %CBOR.Tag{tag: :bytes, value: der} -> der end) == chain
  end

  describe "issuerAuth algorithm policy" do
    @issuer_algs ["ES256", "ES384", "ES512"]
    @issuer_pairs [{-7, "ES256", "P-256"}, {-35, "ES384", "P-384"}, {-36, "ES512", "P-521"}]

    setup ctx do
      {:ok, issued} = Mdoc.issue(ctx.opts)
      %{issuer_signed: issued |> Base.url_decode64!(padding: false) |> decode!(), root: X509Fixture.root()}
    end

    for {alg, name, curve} <- @issuer_pairs do
      @alg alg
      @name name
      @curve curve

      test "accepts #{@name}/#{@curve} with JWK, JOSE key and PEM when configured", ctx do
        key = JOSE.JWK.generate_key({:ec, @curve})
        signed = ctx.issuer_signed |> CoseFixture.resign_issuer(key, @alg) |> CBOR.encode()
        public_key = JOSE.JWK.to_public(key)

        for trusted <- [public_key, elem(JOSE.JWK.to_public_map(key), 1), elem(JOSE.JWK.to_pem(public_key), 1)] do
          assert {:ok, result} = Mdoc.verify(signed, trusted, now: ctx.now, accepted_algs: @issuer_algs)
          assert result.namespaces[@mdl_namespace]["given_name"] == "Jane"
        end

        if @name != "ES256" do
          assert {:error, :unsupported_algorithm} = Mdoc.verify(signed, public_key, now: ctx.now)

          assert {:error, :unsupported_algorithm} =
                   Mdoc.verify(signed, public_key, now: ctx.now, accepted_algs: ["ES256"])
        end

        assert {:error, :unsupported_algorithm} = Mdoc.verify(signed, public_key, accepted_algs: [])
      end

      test "accepts #{@name}/#{@curve} from the validated certificate leaf", ctx do
        issuer = algorithm_certificate(ctx.root, @curve)

        signed =
          ctx.issuer_signed
          |> CoseFixture.resign_issuer(issuer.key, @alg, unprotected: %{33 => Enum.map(issuer.chain, &bytes/1)})
          |> CBOR.encode()

        opts = [trusted_certificates: issuer.anchors, now: ctx.now, accepted_algs: @issuer_algs]
        assert {:ok, _} = Mdoc.verify(signed, nil, opts)

        if @name != "ES256" do
          assert {:error, :unsupported_algorithm} =
                   Mdoc.verify(signed, nil, Keyword.put(opts, :accepted_algs, ["ES256"]))
        end
      end
    end

    for {alg, name, expected_curve} <- @issuer_pairs,
        {_other_alg, _other_name, curve} <- @issuer_pairs,
        curve != expected_curve do
      @alg alg
      @name name
      @curve curve

      test "refuses #{@name}/#{@curve} with a pairing error for supplied and leaf keys", ctx do
        issuer = algorithm_certificate(ctx.root, @curve)

        signed =
          ctx.issuer_signed
          |> CoseFixture.resign_issuer(issuer.key, @alg, unprotected: %{33 => Enum.map(issuer.chain, &bytes/1)})
          |> CBOR.encode()

        # A misleading JWK alg cannot override its actual EC curve.
        public = Map.put(issuer.public_key, "alg", @name)
        assert {:error, :algorithm_key_mismatch} = Mdoc.verify(signed, public, accepted_algs: @issuer_algs)

        assert {:error, :algorithm_key_mismatch} =
                 Mdoc.verify(signed, nil, trusted_certificates: issuer.anchors, accepted_algs: @issuer_algs)

        assert {:error, :algorithm_key_mismatch} = Mdoc.verify(signed, public)
      end
    end

    defp algorithm_certificate(root, curve) do
      oid =
        Map.fetch!(
          %{"P-256" => {1, 2, 840, 10_045, 3, 1, 7}, "P-384" => {1, 3, 132, 0, 34}, "P-521" => {1, 3, 132, 0, 35}},
          curve
        )

      X509Fixture.chain(root, peer: [key: {:namedCurve, oid}, extensions: [X509Fixture.signer_usage()]])
    end
  end

  describe "issue/1 :key_authorizations" do
    setup do
      {issuer_pem, issuer_public} = keypair()
      {_holder_pem, holder_public} = keypair()

      %{
        issuer_pem: issuer_pem,
        issuer_public: issuer_public,
        holder_public: holder_public,
        now: System.system_time(:second)
      }
    end

    test "is written to the MSO and returned by verify/3", ctx do
      authorizations = [name_spaces: ["org.example.device"], data_elements: %{@mdl_namespace => ["age_over_21"]}]

      assert {:ok, issued} =
               Mdoc.issue(issue_opts(ctx.issuer_pem, ctx.holder_public, ctx.now, key_authorizations: authorizations))

      assert {:ok, verified} = Mdoc.verify(issued, ctx.issuer_public, now: ctx.now)

      assert verified.key_authorizations == %{
               name_spaces: ["org.example.device"],
               data_elements: %{@mdl_namespace => ["age_over_21"]}
             }
    end

    test "is absent from the MSO when not given", ctx do
      assert {:ok, issued} = Mdoc.issue(issue_opts(ctx.issuer_pem, ctx.holder_public, ctx.now, []))
      assert {:ok, verified} = Mdoc.verify(issued, ctx.issuer_public, now: ctx.now)
      assert verified.key_authorizations == %{name_spaces: [], data_elements: %{}}

      [_protected, _unprotected, %CBOR.Tag{tag: :bytes, value: payload}, _signature] =
        issued |> Base.url_decode64!(padding: false) |> decode!() |> Access.get("issuerAuth")

      %CBOR.Tag{tag: 24, value: %CBOR.Tag{tag: :bytes, value: mso_bytes}} = decode!(payload)
      refute Map.has_key?(decode!(mso_bytes)["deviceKeyInfo"], "keyAuthorizations")
    end

    test "refuses an empty authorization, a namespace listed both ways, and malformed values", ctx do
      for invalid <- [
            [],
            %{},
            [name_spaces: []],
            [data_elements: %{}],
            [name_spaces: ["ns"], data_elements: %{"ns" => ["a"]}],
            [name_spaces: [""]],
            [name_spaces: ["ns", "ns"]],
            [name_spaces: "ns"],
            [data_elements: %{"ns" => []}],
            [data_elements: %{"ns" => [""]}],
            [data_elements: %{"" => ["a"]}],
            [data_elements: [{"ns", ["a"]}]],
            [name_spaces: ["ns"], other: true],
            "ns"
          ] do
        assert {:error, :invalid_options} =
                 Mdoc.issue(issue_opts(ctx.issuer_pem, ctx.holder_public, ctx.now, key_authorizations: invalid)),
               "#{inspect(invalid)} was accepted"
      end
    end
  end

  describe "verify_device_response/4" do
    setup do
      {issuer_pem, issuer_public} = keypair()
      {holder_pem, holder_public} = keypair()
      now = System.system_time(:second)

      namespaces = %{
        @mdl_namespace => %{
          "birth_date" => "1990-01-02",
          "family_name" => "Doe",
          "given_name" => "Jane"
        }
      }

      # The device key may sign `age_over_21` in the mDL namespace, and
      # anything in `org.example.device`.
      {:ok, issued} =
        Mdoc.issue(
          issue_opts(issuer_pem, holder_public, now,
            namespaces: namespaces,
            key_authorizations: [
              name_spaces: ["org.example.device"],
              data_elements: %{@mdl_namespace => ["age_over_21"]}
            ]
          )
        )

      issuer_signed = issued |> Base.url_decode64!(padding: false) |> decode!()

      {:ok, issued_without_authorizations} =
        Mdoc.issue(issue_opts(issuer_pem, holder_public, now, namespaces: namespaces))

      %{
        client_id: "x509_san_dns:verifier.example.com",
        holder_pem: holder_pem,
        issuer_public: issuer_public,
        issuer_signed: issuer_signed,
        issuer_signed_without_authorizations:
          issued_without_authorizations |> Base.url_decode64!(padding: false) |> decode!(),
        namespaces: namespaces,
        now: now,
        nonce: "n-0S6_WzA2Mj",
        response_uri: "https://verifier.example.com/response"
      }
    end

    # Builds a DeviceResponse the way a wallet would: sign DeviceAuthentication
    # (per ISO 18013-5 §9.1.3.4) over a SessionTranscript whose Handover is
    # OID4VP's OpenID4VPHandover (redirect flow, per OID4VP 1.0 "Handover and
    # SessionTranscript Definitions"), independently of Mdoc's own (private)
    # construction of the same structures.
    defp build_device_response(ctx, overrides \\ []) do
      client_id = Keyword.get(overrides, :client_id, ctx.client_id)
      nonce = Keyword.get(overrides, :nonce, ctx.nonce)
      response_uri = Keyword.get(overrides, :response_uri, ctx.response_uri)
      jwk_thumbprint = Keyword.get(overrides, :jwk_thumbprint)
      doc_type = Keyword.get(overrides, :doc_type, @doc_type)
      device_namespaces = Keyword.get(overrides, :device_namespaces, %{})
      device_auth = Keyword.get(overrides, :device_auth)
      status = Keyword.get(overrides, :status, 0)

      session_transcript =
        Keyword.get(overrides, :session_transcript, session_transcript(client_id, nonce, response_uri, jwk_thumbprint))

      device_namespaces_tagged = tagged(device_namespaces)

      device_auth =
        device_auth ||
          {"deviceSignature",
           sign_device_auth(
             ctx.holder_pem,
             device_authentication_bytes(session_transcript, doc_type, device_namespaces_tagged)
           )}

      {device_auth_key, device_auth_value} = device_auth

      document = %{
        "docType" => doc_type,
        "issuerSigned" => ctx.issuer_signed,
        "deviceSigned" => %{
          "nameSpaces" => device_namespaces_tagged,
          "deviceAuth" => %{device_auth_key => device_auth_value}
        }
      }

      %{"documents" => [document], "status" => status, "version" => "1.0"}
      |> CBOR.encode()
      |> Base.url_encode64(padding: false)
    end

    defp session_transcript(client_id, nonce, response_uri, jwk_thumbprint) do
      handover_info_hash =
        [client_id, nonce, jwk_thumbprint, response_uri]
        |> CBOR.encode()
        |> then(&:crypto.hash(:sha256, &1))
        |> bytes()

      [nil, nil, ["OpenID4VPHandover", handover_info_hash]]
    end

    defp device_authentication_bytes(session_transcript, doc_type, device_namespaces_tagged) do
      ["DeviceAuthentication", session_transcript, doc_type, device_namespaces_tagged]
      |> tagged()
      |> CBOR.encode()
    end

    defp sign_device_auth(holder_pem, device_authentication_bytes) do
      holder_pem
      |> Cose.sign1_detached(device_authentication_bytes, [])
      |> decode!()
    end

    defp tagged(value), do: %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(value))}

    defp context(ctx, overrides \\ []) do
      [client_id: ctx.client_id, nonce: ctx.nonce, response_uri: ctx.response_uri]
      |> Keyword.merge(overrides)
    end

    test "verifies a valid presentation and returns doc_type, disclosed elements, and device namespaces", ctx do
      device_response = build_device_response(ctx, device_namespaces: %{@mdl_namespace => %{"age_over_21" => true}})

      assert {:ok, [verified]} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)

      assert verified.doc_type == @doc_type
      assert verified.namespaces == ctx.namespaces
      assert verified.device_namespaces == %{@mdl_namespace => %{"age_over_21" => true}}
    end

    test "accepts device-signed elements the MSO authorizes, by element or by namespace", ctx do
      for device_namespaces <- [
            %{},
            %{@mdl_namespace => %{"age_over_21" => true}},
            %{"org.example.device" => %{"note" => "any element in an authorized namespace"}},
            %{@mdl_namespace => %{"age_over_21" => true}, "org.example.device" => %{"a" => 1, "b" => 2}}
          ] do
        device_response = build_device_response(ctx, device_namespaces: device_namespaces)

        assert {:ok, [verified]} =
                 Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)

        assert verified.device_namespaces == device_namespaces
      end
    end

    test "refuses a device-signed element the MSO does not authorize (ISO/IEC 18013-5 §9.1.3.4)", ctx do
      for device_namespaces <- [
            # A namespace the MSO names nowhere.
            %{"org.example.unlisted" => %{"note" => "signed by the device key"}},
            # An authorized namespace's element list does not cover this one.
            %{@mdl_namespace => %{"age_over_18" => true}},
            # One authorized element beside one that is not.
            %{@mdl_namespace => %{"age_over_21" => true, "family_name" => "Roe"}},
            # An authorized namespace beside one that is not.
            %{"org.example.device" => %{"a" => 1}, "org.example.unlisted" => %{"a" => 1}}
          ] do
        device_response = build_device_response(ctx, device_namespaces: device_namespaces)

        assert {:error, :unauthorized_device_element} =
                 Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now),
               "#{inspect(device_namespaces)} was accepted"
      end
    end

    test "an MSO with no keyAuthorizations authorizes no device-signed element", ctx do
      ctx = %{ctx | issuer_signed: ctx.issuer_signed_without_authorizations}

      empty = build_device_response(ctx, device_namespaces: %{})

      assert {:ok, [%{device_namespaces: %{}}]} =
               Mdoc.verify_device_response(empty, context(ctx), ctx.issuer_public, now: ctx.now)

      signed = build_device_response(ctx, device_namespaces: %{@mdl_namespace => %{"age_over_21" => true}})

      assert {:error, :unauthorized_device_element} =
               Mdoc.verify_device_response(signed, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "a forged device signature is reported before the authorization check", ctx do
      {other_pem, _other_public} = keypair()

      device_response =
        build_device_response(%{ctx | holder_pem: other_pem},
          device_namespaces: %{"org.example.unlisted" => %{"a" => 1}}
        )

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "rejects a CBOR tag where DeviceNameSpaces requires a plain map", ctx do
      tagged_map = %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(%{}))}
      device_response = build_device_response(ctx, device_namespaces: tagged_map)

      assert {:error, :invalid_mdoc} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "rejects DeviceNameSpaces with non-map DeviceSignedItems or non-string identifiers", ctx do
      for invalid_device_ns <- [
            %{@mdl_namespace => 123},
            %{@mdl_namespace => ["not", "a", "map"]},
            %{@mdl_namespace => %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(%{}))}},
            %{"" => %{"age_over_21" => true}},
            %{123 => %{"age_over_21" => true}},
            %{@mdl_namespace => %{"" => true}},
            %{@mdl_namespace => %{123 => true}}
          ] do
        device_response = build_device_response(ctx, device_namespaces: invalid_device_ns)

        assert {:error, :invalid_mdoc} =
                 Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now),
               "expected :invalid_mdoc for device_namespaces=#{inspect(invalid_device_ns)}"
      end
    end

    test "rejects a DeviceResponse with a missing or unsupported version", ctx do
      raw = ctx |> build_device_response() |> Base.url_decode64!(padding: false) |> decode!()

      for bad_response <- [
            Map.delete(raw, "version"),
            Map.put(raw, "version", "0.9"),
            Map.put(raw, "version", "2.0"),
            Map.put(raw, "version", 1)
          ] do
        encoded = bad_response |> CBOR.encode() |> Base.url_encode64(padding: false)

        assert {:error, :invalid_mdoc} =
                 Mdoc.verify_device_response(encoded, context(ctx), ctx.issuer_public, now: ctx.now),
               "expected :invalid_mdoc for version=#{inspect(Map.get(bad_response, "version"))}"
      end
    end

    test "a mismatched nonce fails device-auth signature verification", ctx do
      device_response = build_device_response(ctx)

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(device_response, context(ctx, nonce: "different-nonce"), ctx.issuer_public,
                 now: ctx.now
               )
    end

    test "a mismatched client_id fails device-auth signature verification", ctx do
      device_response = build_device_response(ctx)

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(
                 device_response,
                 context(ctx, client_id: "x509_san_dns:attacker.example.com"),
                 ctx.issuer_public,
                 now: ctx.now
               )
    end

    test "a mismatched response_uri fails device-auth signature verification", ctx do
      device_response = build_device_response(ctx)

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(
                 device_response,
                 context(ctx, response_uri: "https://attacker.example.com/response"),
                 ctx.issuer_public,
                 now: ctx.now
               )
    end

    test "a tampered deviceAuth signature is rejected", ctx do
      device_response = build_device_response(ctx)
      raw = Base.url_decode64!(device_response, padding: false)
      %{"documents" => [document]} = decode!(raw)

      %{"deviceAuth" => %{"deviceSignature" => [protected, unprotected, payload, signature_value]}} =
        document["deviceSigned"]

      %CBOR.Tag{tag: :bytes, value: <<prefix::binary-size(63), last>>} = signature_value
      tampered_signature = bytes(prefix <> <<:erlang.bxor(last, 1)>>)

      tampered_document =
        put_in(document, ["deviceSigned", "deviceAuth", "deviceSignature"], [
          protected,
          unprotected,
          payload,
          tampered_signature
        ])

      device_response =
        %{"documents" => [tampered_document], "status" => 0, "version" => "1.0"}
        |> CBOR.encode()
        |> Base.url_encode64(padding: false)

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "an outer docType that disagrees with the MSO docType is rejected", ctx do
      device_response = build_device_response(ctx, doc_type: "eu.europa.ec.eudi.pid.1")

      assert {:error, :unexpected_doc_type} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "expected_doc_type rejects a presentation of a different document type", ctx do
      device_response = build_device_response(ctx)

      assert {:error, :unexpected_doc_type} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public,
                 expected_doc_type: "eu.europa.ec.eudi.pid.1",
                 now: ctx.now
               )
    end

    test "COSE_Mac0 device authentication is not supported", ctx do
      device_response =
        build_device_response(ctx, device_auth: {"deviceMac", [bytes(<<>>), %{}, nil, bytes(<<0::256>>)]})

      assert {:error, :unsupported_algorithm} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "a DeviceResponse status other than OK is rejected", ctx do
      device_response = build_device_response(ctx, status: 11)

      assert {:error, :invalid_mdoc} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "a direct_post.jwt presentation binds the Verifier's response-encryption key", ctx do
      {_verifier_pem, verifier_jwk} = keypair()
      {:ok, encoded_thumbprint} = Thumbprint.of_jwk(verifier_jwk)
      jwk_thumbprint = encoded_thumbprint |> Base.url_decode64!(padding: false) |> bytes()

      device_response = build_device_response(ctx, jwk_thumbprint: jwk_thumbprint)

      assert {:ok, [verified]} =
               Mdoc.verify_device_response(
                 device_response,
                 context(ctx, response_encryption_jwk: verifier_jwk),
                 ctx.issuer_public,
                 now: ctx.now
               )

      assert verified.doc_type == @doc_type
    end

    test "a direct_post.jwt presentation rejects a mismatched response-encryption key", ctx do
      {_verifier_pem, verifier_jwk} = keypair()
      {_other_pem, other_jwk} = keypair()
      {:ok, encoded_thumbprint} = Thumbprint.of_jwk(verifier_jwk)
      jwk_thumbprint = encoded_thumbprint |> Base.url_decode64!(padding: false) |> bytes()

      device_response = build_device_response(ctx, jwk_thumbprint: jwk_thumbprint)

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(
                 device_response,
                 context(ctx, response_encryption_jwk: other_jwk),
                 ctx.issuer_public,
                 now: ctx.now
               )
    end

    test "session_transcript/1 and device_authentication_bytes/3 match an independent construction", ctx do
      {_verifier_pem, verifier_jwk} = keypair()
      {:ok, encoded_thumbprint} = Thumbprint.of_jwk(verifier_jwk)
      jwk_thumbprint = encoded_thumbprint |> Base.url_decode64!(padding: false) |> bytes()
      device_namespaces = tagged(%{@mdl_namespace => %{"age_over_21" => true}})

      assert {:ok, plain} = Mdoc.session_transcript(context(ctx))
      assert plain == session_transcript(ctx.client_id, ctx.nonce, ctx.response_uri, nil)

      assert {:ok, encrypted} = Mdoc.session_transcript(context(ctx, response_encryption_jwk: verifier_jwk))
      assert encrypted == session_transcript(ctx.client_id, ctx.nonce, ctx.response_uri, jwk_thumbprint)

      assert Mdoc.device_authentication_bytes(encrypted, @doc_type, device_namespaces) ==
               device_authentication_bytes(encrypted, @doc_type, device_namespaces)
    end

    test "a response signed over the public session transcript verifies", ctx do
      {:ok, transcript} = Mdoc.session_transcript(context(ctx))
      device_namespaces = tagged(%{})
      signed = Mdoc.device_authentication_bytes(transcript, @doc_type, device_namespaces)

      device_response =
        build_device_response(ctx, device_auth: {"deviceSignature", sign_device_auth(ctx.holder_pem, signed)})

      assert {:ok, [_verified]} =
               Mdoc.verify_device_response(device_response, context(ctx), ctx.issuer_public, now: ctx.now)
    end

    test "session_transcript/1 rejects a missing value and an unusable encryption key", ctx do
      for key <- [:client_id, :nonce, :response_uri] do
        assert {:error, :invalid_context} = Mdoc.session_transcript(Keyword.delete(context(ctx), key))
        assert {:error, :invalid_context} = Mdoc.session_transcript(Keyword.put(context(ctx), key, ""))
      end

      assert {:error, :invalid_context} = Mdoc.session_transcript(Process.get(:never_set, %{}))

      assert {:error, :invalid_key} =
               Mdoc.session_transcript(context(ctx, response_encryption_jwk: %{"kty" => "EC"}))
    end

    test "DC API transcript matches the OpenID4VP 1.0 B.2.6.2 published example" do
      # https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-b.2.6.2
      jwk = %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
        "y" => "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
        "alg" => "ECDH-ES",
        "use" => "enc",
        "kid" => "1"
      }

      assert {:ok, transcript} =
               Mdoc.session_transcript(
                 dc_api_origin: "https://example.com",
                 nonce: "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                 response_encryption_jwk: jwk
               )

      expected =
        "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4" <>
          "212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"

      assert CBOR.encode(transcript) == Base.decode16!(expected, case: :lower)
    end

    test "DC API binds exact origins, nonce and flow with independent device signatures", ctx do
      origin = "https://verifier.example.com"
      dc_context = [dc_api_origin: origin, nonce: ctx.nonce]
      transcript = dc_api_transcript(origin, ctx.nonce, nil)
      assert {:ok, ^transcript} = Mdoc.session_transcript(dc_context)
      dc_presentation = build_device_response(ctx, session_transcript: transcript)
      redirect_presentation = build_device_response(ctx)

      assert {:ok, [_]} = Mdoc.verify_device_response(dc_presentation, dc_context, ctx.issuer_public, now: ctx.now)

      for altered <- [
            Keyword.put(dc_context, :dc_api_origin, "https://other.example.com"),
            Keyword.put(dc_context, :nonce, "different"),
            context(ctx)
          ] do
        assert {:error, :invalid_signature} =
                 Mdoc.verify_device_response(dc_presentation, altered, ctx.issuer_public, now: ctx.now)
      end

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(redirect_presentation, dc_context, ctx.issuer_public, now: ctx.now)

      prefixed = build_device_response(ctx, session_transcript: dc_api_transcript("origin:" <> origin, ctx.nonce, nil))

      assert {:error, :invalid_signature} =
               Mdoc.verify_device_response(prefixed, dc_context, ctx.issuer_public, now: ctx.now)

      assert {:error, :invalid_context} =
               Mdoc.session_transcript(Keyword.put(dc_context, :dc_api_origin, "origin:" <> origin))
    end

    test "DC API accepts serialized non-default ports and platform application origins", ctx do
      for origin <- [
            "https://verifier.example.com:8443",
            "http://localhost:8080",
            "https://[::1]:8443",
            "platform:pkg-key-hash:Z4OFzVVSZrzTRa3eg79hUuHy12MVW0vzPDf4q4zaPs0"
          ] do
        assert {:ok, transcript} = Mdoc.session_transcript(dc_api_origin: origin, nonce: ctx.nonce)
        assert transcript == dc_api_transcript(origin, ctx.nonce, nil)
      end

      for bad <- [
            nil,
            "",
            "origin:https://verifier.example.com",
            "https://verifier.example.com/",
            "https://verifier.example.com:443",
            "http://localhost:80",
            "https://verifier.example.com?q=1",
            "https://user@verifier.example.com",
            "https://VERIFIER.example.com",
            "https://verifier.example.com#x",
            "https://verifier.example.com:65536",
            "https://[invalid]",
            "https://verifier%2eexample.com",
            "https://verifier.example.com\n",
            <<255>>,
            :invalid
          ] do
        assert {:error, :invalid_context} = Mdoc.session_transcript(dc_api_origin: bad, nonce: ctx.nonce)
      end

      assert {:error, :invalid_context} = Mdoc.session_transcript(dc_api_origin: "https://example.com")
      assert {:error, :invalid_context} = Mdoc.session_transcript([:not_a_keyword])

      assert {:error, :invalid_key} =
               Mdoc.session_transcript(
                 dc_api_origin: "https://example.com",
                 nonce: ctx.nonce,
                 response_encryption_jwk: %{}
               )
    end

    test "issuer algorithm acceptance does not broaden device authentication", ctx do
      transcript = session_transcript(ctx.client_id, ctx.nonce, ctx.response_uri, nil)
      payload = device_authentication_bytes(transcript, @doc_type, tagged(%{}))
      holder = JOSE.JWK.from_pem(ctx.holder_pem)

      for alg <- [-35, -36] do
        signature = CoseFixture.sign1(payload, holder, alg, detached: true)
        presentation = build_device_response(ctx, device_auth: {"deviceSignature", signature})

        assert {:error, :algorithm_key_mismatch} =
                 Mdoc.verify_device_response(presentation, context(ctx), ctx.issuer_public,
                   now: ctx.now,
                   accepted_algs: ["ES256", "ES384", "ES512"]
                 )
      end
    end

    defp dc_api_transcript(origin, nonce, thumbprint) do
      digest = :crypto.hash(:sha256, CBOR.encode([origin, nonce, thumbprint]))
      [nil, nil, ["OpenID4VPDCAPIHandover", bytes(digest)]]
    end

    test "missing required context values are rejected", ctx do
      device_response = build_device_response(ctx)
      incomplete_context = Keyword.delete(context(ctx), :nonce)

      assert {:error, :invalid_mdoc} =
               Mdoc.verify_device_response(device_response, incomplete_context, ctx.issuer_public, now: ctx.now)
    end
  end

  test "rejects a DeviceResponse in which a map repeats a key" do
    encode = fn bytes -> Base.url_encode64(bytes, padding: false) end
    document = CBOR.encode(%{"docType" => "org.iso.18013.5.1.mDL"})

    # {"version": "1.0", "documents": [{"docType": ...}], "status": 0}
    control =
      <<0xA3>> <>
        CBOR.encode("version") <>
        CBOR.encode("1.0") <>
        CBOR.encode("documents") <> <<0x81>> <> document <> CBOR.encode("status") <> <<0x00>>

    assert {:ok, "org.iso.18013.5.1.mDL"} = Mdoc.peek_doc_type(encode.(control))

    # The same response with "documents" a second time, naming another type.
    # A decoder that keeps one of the two would read whichever it kept.
    other = CBOR.encode(%{"docType" => "org.example.other"})

    repeated =
      <<0xA4>> <>
        CBOR.encode("version") <>
        CBOR.encode("1.0") <>
        CBOR.encode("documents") <>
        <<0x81>> <>
        document <>
        CBOR.encode("documents") <> <<0x81>> <> other <> CBOR.encode("status") <> <<0x00>>

    assert {:error, :invalid_mdoc} = Mdoc.peek_doc_type(encode.(repeated))

    # A repeat inside the document map is refused as well.
    nested =
      <<0xA3>> <>
        CBOR.encode("version") <>
        CBOR.encode("1.0") <>
        CBOR.encode("documents") <>
        <<0x81, 0xA2>> <>
        CBOR.encode("docType") <>
        CBOR.encode("org.iso.18013.5.1.mDL") <>
        CBOR.encode("docType") <> CBOR.encode("org.example.other") <> CBOR.encode("status") <> <<0x00>>

    assert {:error, :invalid_mdoc} = Mdoc.peek_doc_type(encode.(nested))
  end

  test "rejects oversized deeply nested CBOR before decoding" do
    nested_arrays = :binary.copy(<<0x81>>, 262_145)
    assert {:error, :invalid_mdoc} = Mdoc.peek_doc_type(nested_arrays)
  end
end
