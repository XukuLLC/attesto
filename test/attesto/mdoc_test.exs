defmodule Attesto.MdocTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{Cose, Mdoc, Thumbprint}

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

      {:ok, issued} = Mdoc.issue(issue_opts(issuer_pem, holder_public, now, namespaces: namespaces))
      issuer_signed = issued |> Base.url_decode64!(padding: false) |> decode!()

      %{
        client_id: "x509_san_dns:verifier.example.com",
        holder_pem: holder_pem,
        issuer_public: issuer_public,
        issuer_signed: issuer_signed,
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

      session_transcript = session_transcript(client_id, nonce, response_uri, jwk_thumbprint)
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

    test "missing required context values are rejected", ctx do
      device_response = build_device_response(ctx)
      incomplete_context = Keyword.delete(context(ctx), :nonce)

      assert {:error, :invalid_mdoc} =
               Mdoc.verify_device_response(device_response, incomplete_context, ctx.issuer_public, now: ctx.now)
    end
  end
end
