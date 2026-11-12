defmodule Attesto.X509Test do
  use ExUnit.Case, async: true

  alias Attesto.Test.X509Fixture, as: Fixture
  alias Attesto.X509

  setup_all do
    root = Fixture.root()
    %{root: root, issuer: Fixture.chain(root)}
  end

  test "returns the verified leaf public JWK and unique base64url authority identifiers", ctx do
    aki = {:Extension, {2, 5, 29, 35}, false, {:AuthorityKeyIdentifier, <<255, 1, 2>>, :asn1_NOVALUE, :asn1_NOVALUE}}
    issuer = Fixture.chain(ctx.root, peer: [extensions: [aki]])
    assert {:ok, verified} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors)
    assert verified.public_key == issuer.public_key
    assert verified.authority_key_identifiers == [Base.url_encode64(<<255, 1, 2>>, padding: false)]
  end

  test "validates a leaf-first intermediate chain and generic embedded anchor", ctx do
    issuer = Fixture.chain(ctx.root, intermediates: [[key: Fixture.curve()]])
    assert {:ok, _} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors)
    assert {:ok, _} = X509.verify(issuer.chain ++ issuer.anchors, trusted_certificates: issuer.anchors)
    assert {:error, _} = X509.verify(Enum.reverse(issuer.chain), trusted_certificates: issuer.anchors)
    assert {:error, _} = X509.verify([issuer.leaf], trusted_certificates: issuer.anchors)
  end

  test "requires explicit anchors and rejects an unknown root", ctx do
    for anchors <- [nil, [], [:not_der], [""], [Fixture.root().cert]] do
      assert {:error, :untrusted_certificate} = X509.verify(ctx.issuer.chain, trusted_certificates: anchors)
    end

    assert {:error, :untrusted_certificate} = X509.verify([ctx.root.cert], [])
  end

  test "HAIP refuses embedded trust anchors and self-signed leaves", ctx do
    assert {:error, :untrusted_certificate} =
             X509.verify(ctx.issuer.chain ++ ctx.issuer.anchors, trusted_certificates: ctx.issuer.anchors, haip: true)

    assert {:error, :untrusted_certificate} =
             X509.verify([ctx.root.cert], trusted_certificates: [ctx.root.cert], haip: true)
  end

  test "an anchor alone still needs current validity and signing usage" do
    root =
      :public_key.pkix_test_root_cert(~c"synthetic-expired-root",
        key: Fixture.curve(),
        validity: {{2020, 1, 1}, {2020, 1, 2}}
      )

    assert {:error, :untrusted_certificate} = X509.verify([root.cert], trusted_certificates: [root.cert])
  end

  test "callback may deny a trusted path but cannot bypass path validation", ctx do
    assert {:ok, _} =
             X509.verify(ctx.issuer.chain,
               trusted_certificates: ctx.issuer.anchors,
               certificate_trust: fn chain ->
                 assert chain == ctx.issuer.chain
                 :ok
               end
             )

    for callback <- [fn _ -> {:error, :denied} end, fn _ -> true end, :allow] do
      assert {:error, :untrusted_certificate} =
               X509.verify(ctx.issuer.chain, trusted_certificates: ctx.issuer.anchors, certificate_trust: callback)
    end

    assert {:error, :untrusted_certificate} =
             X509.verify(ctx.issuer.chain,
               trusted_certificates: [Fixture.root().cert],
               certificate_trust: fn _ -> flunk("policy must not run before path validation") end
             )
  end

  test "raised and thrown callback failures fail closed", ctx do
    for callback <- [fn _ -> raise "policy failure" end, fn _ -> throw(:denied) end, fn _ -> exit(:denied) end] do
      assert {:error, :invalid_certificate} =
               X509.verify(ctx.issuer.chain, trusted_certificates: ctx.issuer.anchors, certificate_trust: callback)
    end
  end

  test "bounds DER chains and anchors and controls malformed inputs", ctx do
    oversized = :binary.copy("x", 65_537)

    for chain <- [[], [""], [:bad], [oversized], List.duplicate(ctx.issuer.leaf, 9)] do
      assert {:error, :untrusted_certificate} = X509.verify(chain, trusted_certificates: ctx.issuer.anchors)
    end

    for anchors <- [[oversized], List.duplicate(ctx.root.cert, 9)] do
      assert {:error, :untrusted_certificate} = X509.verify(ctx.issuer.chain, trusted_certificates: anchors)
    end

    for {chain, opts} <- [{nil, []}, {ctx.issuer.chain, nil}, {[ctx.issuer.leaf | :bad], []}] do
      assert {:error, :invalid_certificate} = X509.verify(chain, opts)
    end
  end

  test "decodes standard base64 in order within the exact x5c bounds", ctx do
    chain = ctx.issuer.chain ++ ctx.issuer.anchors
    assert {:ok, ^chain} = X509.decode_x5c(Enum.map(chain, &Base.encode64/1))
    limit = :binary.copy(<<255>>, 65_536)
    assert {:ok, [^limit]} = X509.decode_x5c([Base.encode64(limit)])
    assert {:ok, certificates} = X509.decode_x5c(List.duplicate(Base.encode64(ctx.issuer.leaf), 8))
    assert length(certificates) == 8

    for encoded <- [
          nil,
          [],
          [nil],
          [""],
          ["!"],
          [Base.url_encode64(<<255, 255>>, padding: false)],
          [Base.encode64(:binary.copy("x", 65_537))],
          [:binary.copy("x", 87_385)],
          List.duplicate(Base.encode64(ctx.issuer.leaf), 9)
        ] do
      assert {:error, :invalid_certificate} = X509.decode_x5c(encoded)
    end
  end

  test "malformed raw certificates do not invalidate unrelated valid anchors", ctx do
    for malformed <- [<<48, 128, 0, 0>>, <<48, 130, 255>>, <<48, 3, 48, 1, 0>>, ctx.issuer.leaf <> <<0>>] do
      assert {:error, _} = X509.verify([malformed], trusted_certificates: ctx.issuer.anchors)
      assert {:ok, _} = X509.verify(ctx.issuer.chain, trusted_certificates: [malformed | ctx.issuer.anchors])
    end
  end

  test "critical mdoc signer usage is accepted only for an mdoc issuer leaf", ctx do
    issuer = Fixture.chain(ctx.root, peer: [extensions: [Fixture.signer_usage()]])
    assert {:error, :untrusted_certificate} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors)
    assert {:ok, _} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors, purpose: :mdoc_issuer)

    assert {:error, :untrusted_certificate} =
             X509.verify(issuer.chain, trusted_certificates: issuer.anchors, purpose: :other)
  end

  test "mdoc purpose does not accept another usage or unknown critical extensions", ctx do
    wrong_usage = {:Extension, {2, 5, 29, 37}, true, [{1, 3, 6, 1, 5, 5, 7, 3, 1}]}
    unknown = {:Extension, {1, 2, 3, 4}, true, <<5, 0>>}

    for extensions <- [[wrong_usage], [Fixture.signer_usage(), unknown]] do
      issuer = Fixture.chain(ctx.root, peer: [extensions: extensions])

      assert {:error, :untrusted_certificate} =
               X509.verify(issuer.chain, trusted_certificates: issuer.anchors, purpose: :mdoc_issuer)
    end
  end

  test "mdoc purpose retains time, chain, signature and key usage validation", ctx do
    issuer = Fixture.chain(ctx.root, peer: [extensions: [Fixture.signer_usage()]])
    opts = [trusted_certificates: issuer.anchors, purpose: :mdoc_issuer]

    assert {:error, :untrusted_certificate} =
             X509.verify(issuer.chain, Keyword.put(opts, :trusted_certificates, [Fixture.root().cert]))

    assert {:error, _} = X509.verify([Fixture.tamper(issuer.leaf)], opts)

    expired =
      Fixture.chain(ctx.root, peer: [extensions: [Fixture.signer_usage()], validity: {{2020, 1, 1}, {2020, 1, 2}}])

    assert {:error, :untrusted_certificate} = X509.verify(expired.chain, opts)

    conflict =
      Fixture.replace_extension(
        issuer.leaf,
        ctx.root.key,
        {2, 5, 29, 15},
        {:Extension, {2, 5, 29, 15}, false, [:keyAgreement]}
      )

    assert {:error, :untrusted_certificate} = X509.verify([conflict], opts)
  end

  test "mdoc purpose does not recognize document signer usage on an intermediate CA", ctx do
    issuer = Fixture.chain(ctx.root, intermediates: [[key: Fixture.curve(), extensions: [Fixture.signer_usage()]]])

    assert {:error, :untrusted_certificate} =
             X509.verify(issuer.chain, trusted_certificates: issuer.anchors, purpose: :mdoc_issuer)
  end
end
