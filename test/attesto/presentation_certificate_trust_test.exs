defmodule Attesto.PresentationCertificateTrustTest do
  use ExUnit.Case, async: false

  alias Attesto.{Cose, JWS, Mdoc, PresentationSession, SdJwtVc, VpToken}
  alias Attesto.PresentationSessionStore.ETS, as: Store
  alias Attesto.Test.X509Fixture, as: Fixture

  @issuer "https://issuer.example"
  @audience "verifier-client"
  @response_uri "https://verifier.example/response"
  @doc_type "org.iso.18013.5.1.mDL"
  @namespace "org.iso.18013.5.1"

  setup_all do
    root = Fixture.root()

    issuer =
      Fixture.named_chain(root, [{:uniformResourceIdentifier, String.to_charlist(@issuer)}],
        intermediates: [[key: Fixture.curve()]],
        peer: [extensions: [Fixture.signer_usage()]]
      )

    # SD-JWT VC uses generic X.509 purpose, so use a separate leaf without mdoc EKU.
    sd_issuer =
      Fixture.named_chain(root, [{:uniformResourceIdentifier, String.to_charlist(@issuer)}],
        intermediates: [[key: Fixture.curve()]]
      )

    %{root: root, mdoc: issuer, sd_jwt_vc: sd_issuer, holder: JOSE.JWK.generate_key({:ec, "P-256"})}
  end

  setup do
    start_supervised!(Store)
    %{now: System.system_time(:second)}
  end

  for format <- [:sd_jwt_vc, :mdoc], api <- [:vp_token, :session] do
    @format format
    @api api

    test "#{api} accepts #{format} anchored certificates and returns verified claims", ctx do
      assert {:ok, %{"identity" => [verified]}} = verify(@api, @format, ctx[@format], ctx)

      if @format == :sd_jwt_vc do
        assert verified.iss == @issuer
        assert verified.claims["given_name"] == "Alice"
      else
        assert verified.doc_type == @doc_type
        assert verified.namespaces[@namespace]["given_name"] == "Alice"
      end
    end

    for failure <- [:unknown_root, :expired_leaf, :self_signed_leaf, :embedded_anchor, :non_ca_intermediate] do
      @failure failure
      test "#{api} refuses #{format} #{@failure} with the core certificate error", ctx do
        fixture = invalid_fixture(@failure, ctx[@format], ctx.root)
        assert verify(@api, @format, fixture, ctx) == error(@api, :untrusted_certificate)
      end
    end

    test "#{api} enforces the #{format} rejecting certificate policy and leaves sessions pending", ctx do
      parent = self()
      fixture = ctx[@format]

      policy = fn chain ->
        send(parent, {:policy, chain})
        {:error, :denied}
      end

      assert verify(@api, @format, fixture, ctx, certificate_trust: policy) == error(@api, :untrusted_certificate)
      assert_received {:policy, chain}
      assert chain == fixture.chain
    end

    test "#{api} forwards haip false for #{format} without bypassing path validation", ctx do
      fixture = invalid_fixture(:embedded_anchor, ctx[@format], ctx.root)
      assert {:ok, _} = verify(@api, @format, fixture, ctx, haip: false)
      fixture = invalid_fixture(:unknown_root, ctx[@format], ctx.root)
      assert verify(@api, @format, fixture, ctx, haip: false) == error(@api, :untrusted_certificate)
    end

    test "#{api} refuses #{format} signed by a key other than the validated leaf", ctx do
      fixture = %{ctx[@format] | key: JOSE.JWK.generate_key({:ec, "P-256"})}
      assert verify(@api, @format, fixture, ctx) == error(@api, :invalid_signature)
    end

    test "#{api} refuses certificate trust combined with keys or resolver for #{format}", ctx do
      parent = self()

      resolver = fn _ ->
        send(parent, :resolver_called)
        {:ok, ctx[@format].public_key}
      end

      for source <- [[issuer_jwks: ctx[@format].public_key], [resolve_issuer: resolver]] do
        assert_raise ArgumentError, fn -> verify(@api, @format, ctx[@format], ctx, source) end
      end

      refute_received :resolver_called
      assert {:ok, _} = verify(@api, @format, ctx[@format], ctx)
      refute_received :resolver_called
    end
  end

  for api <- [:vp_token, :session] do
    @api api
    test "#{api} refuses an SD-JWT leaf naming another issuer", ctx do
      fixture = Fixture.named_chain(ctx.root, [{:uniformResourceIdentifier, ~c"https://other.example"}])
      assert verify(@api, :sd_jwt_vc, fixture, ctx) == error(@api, :certificate_issuer_mismatch)
    end

    test "#{api} accepts mdoc single-bstr x5chain and does not bind docType to certificate names", ctx do
      fixture =
        Fixture.named_chain(ctx.root, [{:uniformResourceIdentifier, ~c"https://other.example"}],
          peer: [extensions: [Fixture.signer_usage()]]
        )

      transform = fn issuer_signed -> put_chain(issuer_signed, bytes(fixture.leaf)) end
      assert {:ok, _} = verify(@api, :mdoc, fixture, ctx, mdoc_transform: transform)
    end

    test "#{api} refuses missing or malformed mdoc x5chain without trying issuer keys", ctx do
      for chain <- [:missing, nil, [], "text", ["text"], bytes(""), [bytes(ctx.mdoc.leaf), 42], bytes("not DER")] do
        transform = fn issuer_signed -> put_chain(issuer_signed, chain) end
        assert verify(@api, :mdoc, ctx.mdoc, ctx, mdoc_transform: transform) == error(@api, :invalid_certificate)
      end
    end

    test "#{api} retains SD-JWT issuer algorithm policy under certificate trust", ctx do
      assert verify(@api, :sd_jwt_vc, ctx.sd_jwt_vc, ctx, accepted_algs: ["PS256"]) == error(@api, :unsupported_alg)
    end
  end

  test "VpToken rejects malformed anchors before inspecting the response", ctx do
    for anchors <- [nil, [], :invalid, "DER", [1], [ctx.root.cert, nil], [ctx.root.cert | :invalid]] do
      assert_raise ArgumentError, ~r/:trusted_certificates/, fn ->
        VpToken.verify(nil, nonce: "nonce", audience: @audience, trusted_certificates: anchors)
      end
    end

    for option <- [[haip: nil], [haip: "false"], [certificate_trust: :invalid], [certificate_trust: fn -> :ok end]] do
      assert_raise ArgumentError, fn ->
        VpToken.verify(nil, [nonce: "nonce", audience: @audience, trusted_certificates: [ctx.root.cert]] ++ option)
      end
    end
  end

  test "session validates certificate anchors on creation and load", ctx do
    for anchors <- [nil, [], :invalid, "DER", [1], [ctx.root.cert, nil], [ctx.root.cert | :invalid]] do
      assert {:error, :invalid_attrs} = PresentationSession.create(Store, attrs({:trusted_certificates, anchors}))
      {:ok, session} = PresentationSession.create(Store, attrs({:trusted_certificates, [ctx.root.cert]}))
      {:ok, entry} = Store.get(session.id)
      :ok = Store.reset()
      :ok = Store.put(put_in(entry, [:data, :issuer_trust], {:trusted_certificates, anchors}))
      assert_raise RuntimeError, fn -> PresentationSession.verify_response(Store, {:id, session.id}, %{}) end
    end
  end

  test "session persists only serializable anchors and rejects runtime anchors with stored keys", ctx do
    for source <- [{:issuer_jwks, ctx.sd_jwt_vc.public_key}, {:resolve_issuer, fn _ -> flunk("resolver called") end}] do
      {:ok, session} = PresentationSession.create(Store, attrs(source))

      assert_raise ArgumentError, fn ->
        PresentationSession.verify_response(Store, {:id, session.id}, %{}, trusted_certificates: [ctx.root.cert])
      end
    end

    {:ok, session} = PresentationSession.create(Store, attrs({:trusted_certificates, [ctx.root.cert]}))
    {:ok, entry} = Store.get(session.id)
    assert :erlang.binary_to_term(:erlang.term_to_binary(entry)) == entry
    refute Map.has_key?(entry.data, :certificate_trust)
    :ok = Store.reset()
    :ok = Store.put(:erlang.binary_to_term(:erlang.term_to_binary(entry)))
    presentation = present(:sd_jwt_vc, ctx.sd_jwt_vc, ctx, session.nonce, [])
    assert {:ok, _} = PresentationSession.verify_response(Store, {:id, session.id}, %{"identity" => [presentation]})
  end

  test "Mdoc.verify uses only the leaf key and never falls back to the trusted argument", ctx do
    issuer_signed = issue_mdoc(ctx.mdoc, ctx)
    opts = [trusted_certificates: [ctx.root.cert]]
    assert {:ok, _} = Mdoc.verify(CBOR.encode(issuer_signed), nil, opts)
    assert {:ok, _} = Mdoc.verify(CBOR.encode(issuer_signed), public(ctx.holder), opts)
    missing = put_chain(issuer_signed, :missing)
    assert {:error, :invalid_certificate} = Mdoc.verify(CBOR.encode(missing), ctx.mdoc.public_key, opts)
    wrong = issue_mdoc(%{ctx.mdoc | key: ctx.holder}, ctx)
    assert {:error, :invalid_signature} = Mdoc.verify(CBOR.encode(wrong), public(ctx.holder), opts)
    assert {:ok, _} = Mdoc.verify(CBOR.encode(missing), ctx.mdoc.public_key)
  end

  defp invalid_fixture(:unknown_root, fixture, _root), do: %{fixture | anchors: [Fixture.root().cert]}
  defp invalid_fixture(:embedded_anchor, fixture, _root), do: %{fixture | chain: fixture.chain ++ fixture.anchors}

  defp invalid_fixture(:expired_leaf, _fixture, root),
    do: Fixture.named_chain(root, [{:dNSName, ~c"issuer.example"}], peer: [validity: {{2000, 1, 1}, {2001, 1, 1}}])

  defp invalid_fixture(:self_signed_leaf, fixture, _root) do
    root =
      :public_key.pkix_test_root_cert(~c"self-signed-leaf",
        key: Fixture.curve(),
        extensions: [
          Fixture.san([{:uniformResourceIdentifier, String.to_charlist(@issuer)}]),
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}},
          {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]}
        ]
      )

    %{fixture | chain: [root.cert], anchors: [root.cert], key: JOSE.JWK.from_key(root.key)}
  end

  defp invalid_fixture(:non_ca_intermediate, fixture, root) do
    [leaf, intermediate] = fixture.chain
    non_ca = {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}}
    intermediate = Fixture.replace_extension(intermediate, root.key, {2, 5, 29, 19}, non_ca)
    %{fixture | chain: [leaf, intermediate]}
  end

  defp verify(api, format, fixture, ctx, opts \\ [])

  defp verify(:vp_token, format, fixture, ctx, opts) do
    presentation = present(format, fixture, ctx, "nonce", opts)

    VpToken.verify(
      %{"identity" => [presentation]},
      [nonce: "nonce", audience: @audience, response_uri: @response_uri, trusted_certificates: fixture.anchors] ++
        Keyword.delete(opts, :mdoc_transform)
    )
  end

  defp verify(:session, format, fixture, ctx, opts) do
    {:ok, session} = PresentationSession.create(Store, attrs({:trusted_certificates, fixture.anchors}))
    presentation = present(format, fixture, ctx, session.nonce, opts)

    result =
      PresentationSession.verify_response(
        Store,
        {:id, session.id},
        %{"identity" => [presentation]},
        Keyword.delete(opts, :mdoc_transform)
      )

    {:ok, entry} = Store.get(session.id)
    assert entry.data.status == if(match?({:ok, _}, result), do: :completed, else: :pending)
    result
  end

  defp attrs(trust),
    do: %{audience: @audience, expected_query_ids: ["identity"], issuer_trust: trust, response_uri: @response_uri}

  defp error(:vp_token, reason), do: {:error, {"identity", reason}}
  defp error(:session, reason), do: {:error, {:invalid_presentation, {"identity", reason}}}

  defp present(:sd_jwt_vc, fixture, ctx, nonce, _opts) do
    vc =
      SdJwtVc.issue([iss: @issuer, vct: "identity", pem: pem(fixture.key)],
        claims: %{"given_name" => "Alice"},
        cnf: %{"jwk" => public(ctx.holder)},
        iat: ctx.now,
        x5c: Enum.map(fixture.chain, &Base.encode64/1)
      )

    kb =
      JWS.sign_compact_jwk(ctx.holder, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
        "nonce" => nonce,
        "aud" => @audience,
        "iat" => ctx.now,
        "sd_hash" => Base.url_encode64(:crypto.hash(:sha256, vc), padding: false)
      })

    vc <> kb
  end

  defp present(:mdoc, fixture, ctx, nonce, opts) do
    issuer_signed = issue_mdoc(fixture, ctx)
    issuer_signed = Keyword.get(opts, :mdoc_transform, &Function.identity/1).(issuer_signed)
    hash = :crypto.hash(:sha256, CBOR.encode([@audience, nonce, nil, @response_uri]))
    transcript = [nil, nil, ["OpenID4VPHandover", bytes(hash)]]
    namespaces = tagged(%{})
    authentication = CBOR.encode(tagged(["DeviceAuthentication", transcript, @doc_type, namespaces]))
    signature = pem(ctx.holder) |> Cose.sign1_detached(authentication, []) |> decode!()

    document = %{
      "docType" => @doc_type,
      "issuerSigned" => issuer_signed,
      "deviceSigned" => %{"nameSpaces" => namespaces, "deviceAuth" => %{"deviceSignature" => signature}}
    }

    Base.url_encode64(CBOR.encode(%{"documents" => [document], "status" => 0, "version" => "1.0"}), padding: false)
  end

  defp issue_mdoc(fixture, ctx) do
    {:ok, issued} =
      Mdoc.issue(
        doc_type: @doc_type,
        namespaces: %{@namespace => %{"given_name" => "Alice"}},
        device_key: public(ctx.holder),
        issuer_pem: pem(fixture.key),
        x5chain: fixture.chain,
        validity: %{signed: ctx.now - 10, valid_from: ctx.now - 5, valid_until: ctx.now + 3600}
      )

    issued |> Base.url_decode64!(padding: false) |> decode!()
  end

  defp put_chain(issuer_signed, chain) do
    [protected, header, payload, signature] = issuer_signed["issuerAuth"]
    header = if chain == :missing, do: Map.delete(header, 33), else: Map.put(header, 33, chain)
    Map.put(issuer_signed, "issuerAuth", [protected, header, payload, signature])
  end

  defp decode!(encoded) do
    {:ok, decoded, ""} = CBOR.decode(encoded)
    decoded
  end

  defp tagged(value), do: %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(value))}
  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}
  defp pem(key), do: key |> JOSE.JWK.to_pem() |> elem(1)
  defp public(key), do: key |> JOSE.JWK.to_public_map() |> elem(1)
end
