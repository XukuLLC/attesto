defmodule Attesto.X509Test do
  use ExUnit.Case, async: true

  alias Attesto.Test.X509Fixture, as: Fixture
  alias Attesto.X509

  require Record

  @records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:otp_certificate, :OTPCertificate, @records[:OTPCertificate])
  Record.defrecordp(:otp_tbs, :OTPTBSCertificate, @records[:OTPTBSCertificate])

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
        digest: :sha256,
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

    for anchors <- [[oversized], List.duplicate(ctx.root.cert, X509.max_trust_anchors() + 1)] do
      assert {:error, :untrusted_certificate} = X509.verify(ctx.issuer.chain, trusted_certificates: anchors)
    end

    many_anchors = [ctx.root.cert | List.duplicate(ctx.issuer.leaf, X509.max_trust_anchors() - 1)]
    assert {:ok, _} = X509.verify(ctx.issuer.chain, trusted_certificates: many_anchors)

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
      refute X509.valid_trust_anchors?([malformed | ctx.issuer.anchors])
      assert {:error, _} = X509.verify([malformed], trusted_certificates: ctx.issuer.anchors)
      assert {:ok, _} = X509.verify(ctx.issuer.chain, trusted_certificates: [malformed | ctx.issuer.anchors])
    end
  end

  test "refuses a digitalSignature leaf with cA TRUE under a separate anchor", ctx do
    extensions = [
      {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, :asn1_NOVALUE}},
      {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]}
    ]

    issuer = Fixture.chain(ctx.root, peer: [extensions: extensions])
    assert {:ok, _} = :public_key.pkix_path_validation(ctx.root.cert, issuer.chain, [])
    assert {:error, :untrusted_certificate} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors)
    assert {:ok, _} = X509.verify(issuer.chain, trusted_certificates: [issuer.leaf])

    %{cert: pinned} =
      :public_key.pkix_test_root_cert(~c"pinned-ca-leaf",
        key: Fixture.curve(),
        digest: :sha256,
        extensions: extensions
      )

    assert X509.valid_trust_anchors?([pinned])
    assert {:ok, %{trust_anchor: ^pinned}} = X509.verify([pinned], trusted_certificates: [pinned])
  end

  test "requires unique extension OIDs in the leaf, intermediate and anchor", ctx do
    first = Fixture.san([{:dNSName, ~c"first.example"}])
    second = Fixture.san([{:dNSName, ~c"second.example"}])

    for extensions <- [[first], [first, second]] do
      %{cert: anchor} =
        root =
        :public_key.pkix_test_root_cert(~c"extension-policy-root",
          key: Fixture.curve(),
          digest: :sha256,
          extensions: extensions
        )

      accepted? = length(extensions) == 1
      assert X509.valid_trust_anchors?([anchor]) == accepted?

      for {issuing_root, opts} <- [
            {ctx.root, [peer: [extensions: extensions]]},
            {ctx.root, [intermediates: [[key: Fixture.curve(), extensions: extensions]]]},
            {root, []}
          ] do
        issuer = Fixture.chain(issuing_root, opts)

        assert {:ok, _} =
                 :public_key.pkix_path_validation(
                   issuing_root.cert,
                   [issuing_root.cert | Enum.reverse(issuer.chain)],
                   []
                 )

        if accepted? do
          assert {:ok, _} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors)
        else
          assert {:error, :untrusted_certificate} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors)
        end
      end
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

  describe "trust anchor constraints and weak signatures" do
    test "pinned end-entity certificate cannot issue child certificates" do
      anchor_key = :public_key.generate_key(Fixture.curve())

      base_root =
        :public_key.pkix_test_root_cert(~c"pinned-ee",
          key: anchor_key,
          digest: :sha256,
          extensions: [
            {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]},
            Fixture.san([{:uniformResourceIdentifier, ~c"https://issuer-a.example"}])
          ]
        )

      # Remove BasicConstraints so anchor is strictly an end-entity cert.
      anchor = Fixture.replace_extension(base_root.cert, anchor_key, {2, 5, 29, 19}, nil)
      assert {:ok, _} = X509.verify([anchor], trusted_certificates: [anchor], haip: false)

      child_key = :public_key.generate_key(Fixture.curve())

      donor =
        :public_key.pkix_test_data(%{
          root: base_root,
          intermediates: [],
          peer: [key: child_key, digest: :sha256]
        })

      tbs = donor[:cert] |> :public_key.pkix_decode_cert(:otp) |> otp_certificate(:tbsCertificate)
      anchor_tbs = anchor |> :public_key.pkix_decode_cert(:otp) |> otp_certificate(:tbsCertificate)

      exts =
        tbs
        |> otp_tbs(:extensions)
        |> Enum.reject(&(elem(&1, 1) in [{2, 5, 29, 19}, {2, 5, 29, 17}]))

      exts = [Fixture.san([{:uniformResourceIdentifier, ~c"https://issuer-b.example"}]) | exts]

      child =
        tbs
        |> otp_tbs(issuer: otp_tbs(anchor_tbs, :subject), extensions: exts)
        |> :public_key.pkix_sign(anchor_key)

      assert {:error, :untrusted_certificate} = X509.verify([child], trusted_certificates: [anchor], haip: false)
    end

    test "self-signed and non-self-signed trust anchors enforce NameConstraints and pathLenConstraint", ctx do
      nc_ext =
        {:Extension, {2, 5, 29, 30}, true,
         {:NameConstraints, [{:GeneralSubtree, {:dNSName, ~c"allowed.example"}, 0, :asn1_NOVALUE}], :asn1_NOVALUE}}

      key = :public_key.generate_key(Fixture.curve())

      nc_root =
        :public_key.pkix_test_root_cert(~c"nc-root",
          key: key,
          digest: :sha256,
          extensions: [
            {:Extension, {2, 5, 29, 15}, false, [:keyCertSign]},
            {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 0}},
            nc_ext
          ]
        )

      bad_leaf = Fixture.named_chain(nc_root, [{:dNSName, ~c"evil.example"}]).leaf
      good_leaf = Fixture.named_chain(nc_root, [{:dNSName, ~c"sub.allowed.example"}]).leaf

      over_pathlen =
        Fixture.named_chain(nc_root, [{:dNSName, ~c"sub.allowed.example"}], intermediates: [[key: Fixture.curve()]])

      assert {:error, :untrusted_certificate} = X509.verify([bad_leaf], trusted_certificates: [nc_root.cert])
      assert {:ok, _} = X509.verify([good_leaf], trusted_certificates: [nc_root.cert])
      assert {:error, :untrusted_certificate} = X509.verify(over_pathlen.chain, trusted_certificates: [nc_root.cert])

      inter_opts = [
        key: Fixture.curve(),
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 15}, false, [:keyCertSign]},
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 0}},
          nc_ext
        ]
      ]

      inter_bad = Fixture.named_chain(ctx.root, [{:dNSName, ~c"evil.example"}], intermediates: [inter_opts])
      inter_bad_anchor = Enum.at(inter_bad.chain, 1)
      assert {:error, :untrusted_certificate} = X509.verify([inter_bad.leaf], trusted_certificates: [inter_bad_anchor])

      inter_ok = Fixture.named_chain(ctx.root, [{:dNSName, ~c"sub.allowed.example"}], intermediates: [inter_opts])
      inter_ok_anchor = Enum.at(inter_ok.chain, 1)
      assert {:ok, _} = X509.verify([inter_ok.leaf], trusted_certificates: [inter_ok_anchor])
      assert {:ok, _} = X509.verify(inter_ok.chain ++ [ctx.root.cert], trusted_certificates: [inter_ok_anchor])
    end

    test "non-self-signed CA anchors match OTP uniformResourceIdentifier NameConstraints semantics", ctx do
      uri_nc_ext =
        {:Extension, {2, 5, 29, 30}, true,
         {:NameConstraints, [{:GeneralSubtree, {:uniformResourceIdentifier, ~c"allowed.example"}, 0, :asn1_NOVALUE}],
          :asn1_NOVALUE}}

      inter_opts = [
        key: Fixture.curve(),
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 15}, false, [:keyCertSign]},
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 0}},
          uri_nc_ext
        ]
      ]

      sub_chain =
        Fixture.named_chain(ctx.root, [{:uniformResourceIdentifier, ~c"https://sub.allowed.example/iss"}],
          intermediates: [inter_opts]
        )

      inter_anchor = Enum.at(sub_chain.chain, 1)
      assert {:error, :untrusted_certificate} = X509.verify(sub_chain.chain, trusted_certificates: [ctx.root.cert])
      assert {:error, :untrusted_certificate} = X509.verify([sub_chain.leaf], trusted_certificates: [inter_anchor])

      exact_chain =
        Fixture.named_chain(ctx.root, [{:uniformResourceIdentifier, ~c"https://allowed.example/iss"}],
          intermediates: [inter_opts]
        )

      exact_anchor = Enum.at(exact_chain.chain, 1)
      assert {:ok, _} = X509.verify([exact_chain.leaf], trusted_certificates: [exact_anchor])
    end

    test "dNSName NameConstraints also constrain uniformResourceIdentifier SANs unless URI constraints exist", ctx do
      dns_nc_ext =
        {:Extension, {2, 5, 29, 30}, true,
         {:NameConstraints, [{:GeneralSubtree, {:dNSName, ~c"allowed.example"}, 0, :asn1_NOVALUE}],
          [{:GeneralSubtree, {:dNSName, ~c"blocked.allowed.example"}, 0, :asn1_NOVALUE}]}}

      nc_root =
        :public_key.pkix_test_root_cert(~c"dns-nc-root",
          key: Fixture.curve(),
          digest: :sha256,
          extensions: [
            {:Extension, {2, 5, 29, 15}, false, [:keyCertSign]},
            {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 1}},
            dns_nc_ext
          ]
        )

      evil_uri = Fixture.named_chain(nc_root, [{:uniformResourceIdentifier, ~c"https://evil.example/iss"}])

      blocked_uri =
        Fixture.named_chain(nc_root, [{:uniformResourceIdentifier, ~c"https://blocked.allowed.example/iss"}])

      hostless_uri = Fixture.named_chain(nc_root, [{:uniformResourceIdentifier, ~c"urn:example:iss"}])
      allowed_uri = Fixture.named_chain(nc_root, [{:uniformResourceIdentifier, ~c"https://sub.allowed.example/iss"}])

      assert {:error, :untrusted_certificate} = X509.verify(evil_uri.chain, trusted_certificates: [nc_root.cert])
      assert {:error, :untrusted_certificate} = X509.verify(blocked_uri.chain, trusted_certificates: [nc_root.cert])
      assert {:error, :untrusted_certificate} = X509.verify(hostless_uri.chain, trusted_certificates: [nc_root.cert])
      assert {:ok, _} = X509.verify(allowed_uri.chain, trusted_certificates: [nc_root.cert])

      excluded_uri_nc_ext =
        {:Extension, {2, 5, 29, 30}, true,
         {:NameConstraints, [{:GeneralSubtree, {:dNSName, ~c"allowed.example"}, 0, :asn1_NOVALUE}],
          [{:GeneralSubtree, {:uniformResourceIdentifier, ~c".blocked.example"}, 0, :asn1_NOVALUE}]}}

      excluded_uri_root =
        :public_key.pkix_test_root_cert(~c"dns-perm-uri-excl-root",
          key: Fixture.curve(),
          digest: :sha256,
          extensions: [
            {:Extension, {2, 5, 29, 15}, false, [:keyCertSign]},
            {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 1}},
            excluded_uri_nc_ext
          ]
        )

      excluded_uri_evil =
        Fixture.named_chain(excluded_uri_root, [{:uniformResourceIdentifier, ~c"https://evil.example/iss"}])

      excluded_uri_allowed =
        Fixture.named_chain(excluded_uri_root, [{:uniformResourceIdentifier, ~c"https://allowed.example/iss"}])

      assert {:error, :untrusted_certificate} =
               X509.verify(excluded_uri_evil.chain, trusted_certificates: [excluded_uri_root.cert])

      assert {:ok, _} = X509.verify(excluded_uri_allowed.chain, trusted_certificates: [excluded_uri_root.cert])

      inter_opts = [
        key: Fixture.curve(),
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 15}, false, [:keyCertSign]},
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 0}},
          dns_nc_ext
        ]
      ]

      inter_evil =
        Fixture.named_chain(ctx.root, [{:uniformResourceIdentifier, ~c"https://evil.example/iss"}],
          intermediates: [inter_opts]
        )

      inter_anchor = Enum.at(inter_evil.chain, 1)
      assert {:error, :untrusted_certificate} = X509.verify([inter_evil.leaf], trusted_certificates: [inter_anchor])
    end

    test "accepts CA-issued end-entity certificate pinned alone when valid and rejects when expired", ctx do
      ee = Fixture.chain(ctx.root)
      assert {:ok, _} = X509.verify([ee.leaf], trusted_certificates: [ee.leaf], haip: false)

      expired_ee =
        Fixture.chain(ctx.root,
          peer: [validity: {{2020, 1, 1}, {2020, 1, 2}}]
        )

      assert {:error, :untrusted_certificate} =
               X509.verify([expired_ee.leaf], trusted_certificates: [expired_ee.leaf], haip: false)
    end

    test "accepts CA-issued mdoc issuer leaf pinned alone and truncates chain above pinned intermediate", ctx do
      mdoc_ee = Fixture.chain(ctx.root, peer: [extensions: [Fixture.signer_usage()]])

      assert {:ok, _} =
               X509.verify([mdoc_ee.leaf],
                 trusted_certificates: [mdoc_ee.leaf],
                 haip: false,
                 purpose: :mdoc_issuer
               )

      inter_chain = Fixture.chain(ctx.root, intermediates: [[key: Fixture.curve()]])
      [leaf, inter] = inter_chain.chain

      assert {:ok, _} =
               X509.verify([leaf, inter, ctx.root.cert], trusted_certificates: [inter], haip: false)

      assert {:error, :untrusted_certificate} =
               X509.verify([leaf, inter, ctx.root.cert],
                 trusted_certificates: [Fixture.root().cert],
                 haip: false
               )
    end

    test "rejects SHA-1 and MD5 signatures on leaves and trust anchors", ctx do
      sha1_root = :public_key.pkix_test_root_cert(~c"sha1-root", key: Fixture.curve(), digest: :sha)

      assert {:error, :untrusted_certificate} =
               X509.verify([sha1_root.cert], trusted_certificates: [sha1_root.cert], haip: false)

      sha1_leaf = Fixture.chain(ctx.root, peer: [digest: :sha])
      assert {:error, :untrusted_certificate} = X509.verify(sha1_leaf.chain, trusted_certificates: ctx.issuer.anchors)
    end

    test "rejects non-boolean :haip and exposes limit and x509_hash helpers", ctx do
      assert {:error, :invalid_certificate} =
               X509.verify(ctx.issuer.chain, trusted_certificates: ctx.issuer.anchors, haip: nil)

      assert X509.max_cert_bytes() == 65_536
      assert X509.max_chain_length() == 8
      assert X509.max_trust_anchors() == 64
      assert X509.valid_trust_anchors?(ctx.issuer.anchors)
      refute X509.valid_trust_anchors?([])
      assert {:ok, "x509_hash:" <> _} = X509.x509_hash_client_id(ctx.issuer.leaf)
      assert {:error, :invalid_certificate} = X509.x509_hash_client_id("")
    end
  end
end
