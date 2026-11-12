defmodule Attesto.SdJwtVcX509Test do
  use ExUnit.Case, async: true

  alias Attesto.{JWS, SdJwt, SdJwtVc}
  alias Attesto.Test.X509Fixture, as: Fixture

  @issuer "https://issuer.example/tenant"

  setup_all do
    root = Fixture.root()

    issuer =
      Fixture.named_chain(root, [{:uniformResourceIdentifier, String.to_charlist(@issuer)}],
        intermediates: [[key: Fixture.curve()]]
      )

    %{root: root, issuer: issuer}
  end

  test "accepts a correct chain to a configured anchor and matching leaf", ctx do
    credential = issue(ctx.issuer)
    assert {:ok, verified} = SdJwtVc.verify(credential, nil, options(ctx))
    assert verified.iss == @issuer
    assert verified.claims["name"] == "Example"
    assert verified.vct == "https://credentials.example/identity"

    unrelated = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map() |> elem(1)
    assert {:ok, ^verified} = SdJwtVc.verify(credential, unrelated, options(ctx))
  end

  test "refuses a self-signed leaf with no anchor", ctx do
    credential = issue(%{ctx.issuer | chain: [ctx.root.cert], key: JOSE.JWK.from_key(ctx.root.key)})

    assert {:error, :untrusted_certificate} =
             SdJwtVc.verify(credential, ctx.issuer.public_key, trusted_certificates: [])
  end

  test "HAIP refuses a chain containing the configured trust anchor", ctx do
    credential = issue(%{ctx.issuer | chain: ctx.issuer.chain ++ ctx.issuer.anchors})
    assert {:error, :untrusted_certificate} = SdJwtVc.verify(credential, nil, options(ctx))
    assert {:ok, _} = SdJwtVc.verify(credential, nil, Keyword.put(options(ctx), :haip, false))
  end

  test "refuses an unknown root even when the caller key and callback allow it", ctx do
    opts = [trusted_certificates: [Fixture.root().cert], certificate_trust: fn _ -> :ok end]
    assert {:error, :untrusted_certificate} = SdJwtVc.verify(issue(ctx.issuer), ctx.issuer.public_key, opts)
  end

  test "refuses an expired leaf regardless of the credential clock override", ctx do
    issuer =
      Fixture.named_chain(ctx.root, [{:dNSName, ~c"issuer.example"}], peer: [validity: {{2020, 1, 1}, {2020, 1, 2}}])

    assert {:error, :untrusted_certificate} =
             SdJwtVc.verify(issue(issuer), nil, Keyword.put(options(ctx), :now, 1_577_836_800))
  end

  test "refuses an intermediate that is not a CA", ctx do
    [leaf, intermediate] = ctx.issuer.chain
    non_ca = {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}}
    intermediate = Fixture.replace_extension(intermediate, ctx.root.key, {2, 5, 29, 19}, non_ca)
    credential = issue(%{ctx.issuer | chain: [leaf, intermediate]})
    assert {:error, :untrusted_certificate} = SdJwtVc.verify(credential, nil, options(ctx))
  end

  test "refuses a leaf naming a different issuer URI", ctx do
    assert {:error, :certificate_issuer_mismatch} =
             SdJwtVc.verify(issue(ctx.issuer, iss: "https://issuer.example/other"), nil, options(ctx))
  end

  test "refuses a leaf naming a different host", ctx do
    issuer = Fixture.named_chain(ctx.root, [{:dNSName, ~c"other.example"}])
    assert {:error, :certificate_issuer_mismatch} = SdJwtVc.verify(issue(issuer), nil, options(ctx))
  end

  test "refuses a URI SAN contradicting an otherwise matching DNS SAN", ctx do
    issuer =
      Fixture.named_chain(ctx.root, [
        {:uniformResourceIdentifier, ~c"https://other.example"},
        {:dNSName, ~c"issuer.example"}
      ])

    assert {:error, :certificate_issuer_mismatch} = SdJwtVc.verify(issue(issuer), nil, options(ctx))
  end

  test "accepts a matching DNS SAN when no URI SAN exists", ctx do
    issuer = Fixture.named_chain(ctx.root, [{:dNSName, ~c"issuer.example"}])
    assert {:ok, _} = SdJwtVc.verify(issue(issuer), nil, options(ctx))
  end

  test "never falls back to supplied keys for missing or malformed x5c or anchors", ctx do
    for anchors <- [nil, [], ["not DER"], :invalid] do
      assert {:error, _} = SdJwtVc.verify(issue(ctx.issuer), ctx.issuer.public_key, trusted_certificates: anchors)
    end

    for x5c <- [nil, [], ["!"], [""], Enum.map(List.duplicate(ctx.issuer.leaf, 9), &Base.encode64/1)] do
      credential = issue(ctx.issuer, x5c: x5c)
      assert {:error, _} = SdJwtVc.verify(credential, ctx.issuer.public_key, options(ctx))
    end
  end

  test "checks JWT signature with the validated leaf key only", ctx do
    wrong = JOSE.JWK.generate_key({:ec, "P-256"})
    credential = issue(%{ctx.issuer | key: wrong})

    assert {:error, :invalid_signature} =
             SdJwtVc.verify(credential, wrong |> JOSE.JWK.to_public_map() |> elem(1), options(ctx))
  end

  test "retains protected header and algorithm checks", ctx do
    credential = issue(ctx.issuer)

    assert {:error, :unsupported_alg} =
             SdJwtVc.verify(credential, nil, Keyword.put(options(ctx), :accepted_algs, ["PS256"]))

    assert {:error, :invalid_typ} = SdJwtVc.verify(issue(ctx.issuer, typ: "JWT"), nil, options(ctx))
    assert {:error, _} = SdJwtVc.verify(resign(credential, ctx.issuer.key, %{"crit" => ["unknown"]}), nil, options(ctx))
    assert {:error, _} = SdJwtVc.verify(:binary.copy("x", 262_145), nil, options(ctx))
  end

  test "certificate mode cannot skip issuer binding and disclosure visibility", ctx do
    opts = Keyword.put(options(ctx), :issuer_identity, :certificate)

    for iss <- [nil, "", 42] do
      assert {:error, _} = SdJwtVc.verify(issue(ctx.issuer, iss: iss), nil, opts)
    end

    credential =
      SdJwt.issue(%{"iss" => @issuer, "vct" => "type"},
        pem: pem(ctx.issuer.key),
        disclosable: ["iss"],
        typ: "dc+sd-jwt",
        x5c: encoded_chain(ctx.issuer)
      )

    assert {:error, :disclosed_registered_claim} = SdJwtVc.verify(credential, nil, opts)
  end

  test "SD-JWT VC cannot opt into the mdoc critical EKU exception", ctx do
    issuer =
      Fixture.named_chain(ctx.root, [{:dNSName, ~c"issuer.example"}], peer: [extensions: [Fixture.signer_usage()]])

    assert {:error, :untrusted_certificate} =
             SdJwtVc.verify(issue(issuer), nil, Keyword.put(options(ctx), :purpose, :mdoc_issuer))
  end

  test "caller-supplied-key verification retains its previous behavior", ctx do
    credential = issue(ctx.issuer, iss: "different-issuer", x5c: ["untrusted header"])
    assert {:ok, %{iss: "different-issuer"}} = SdJwtVc.verify(credential, ctx.issuer.public_key)

    without_iss = issue(ctx.issuer, iss: nil)
    assert {:ok, %{iss: nil}} = SdJwtVc.verify(without_iss, ctx.issuer.public_key, issuer_identity: :certificate)
  end

  test "retains credential expiration, not-before and disclosure verification", ctx do
    now = System.system_time(:second)
    assert {:error, :expired} = SdJwtVc.verify(issue(ctx.issuer, exp: now - 3600), nil, options(ctx))
    assert {:error, :not_yet_valid} = SdJwtVc.verify(issue(ctx.issuer, nbf: now + 3600), nil, options(ctx))
    [jwt, disclosure, ""] = String.split(issue(ctx.issuer), "~")

    assert {:error, :duplicate_digest} =
             SdJwtVc.verify(Enum.join([jwt, disclosure, disclosure, ""], "~"), nil, options(ctx))
  end

  defp issue(issuer, overrides \\ []) do
    claims = %{
      "iss" => Keyword.get(overrides, :iss, @issuer),
      "vct" => "https://credentials.example/identity",
      "name" => "Example"
    }

    claims = if is_nil(claims["iss"]), do: Map.delete(claims, "iss"), else: claims

    claims =
      Enum.reduce(Keyword.take(overrides, [:exp, :nbf]), claims, fn {key, value}, acc ->
        Map.put(acc, Atom.to_string(key), value)
      end)

    SdJwt.issue(claims,
      pem: pem(issuer.key),
      typ: Keyword.get(overrides, :typ, "dc+sd-jwt"),
      disclosable: ["name"],
      x5c: Keyword.get(overrides, :x5c, encoded_chain(issuer))
    )
  end

  defp encoded_chain(issuer), do: Enum.map(issuer.chain, &Base.encode64/1)
  defp pem(key), do: key |> JOSE.JWK.to_pem() |> elem(1)
  defp options(ctx), do: [trusted_certificates: ctx.issuer.anchors, haip: true]

  defp resign(credential, key, header_updates) do
    [jwt | rest] = String.split(credential, "~")
    {:ok, header} = JWS.peek_json(jwt, :protected)
    {:ok, claims} = JWS.peek_json(jwt, :payload)
    signed = JWS.sign_compact_jwk(key, Map.merge(header, header_updates), claims)
    Enum.join([signed | rest], "~")
  end
end
