defmodule Attesto.X509IssuerTest do
  use ExUnit.Case, async: true

  alias Attesto.Test.X509Fixture, as: Fixture
  alias Attesto.X509

  @issuer "https://issuer.example/tenant"

  setup_all do
    %{root: Fixture.root()}
  end

  test "matches the complete issuer URI SAN exactly", ctx do
    leaf = validated_leaf(ctx.root, [{:uniformResourceIdentifier, String.to_charlist(@issuer)}])
    assert X509.matches_issuer?(leaf, @issuer)

    for other <- [
          "https://issuer.example/other",
          "https://other.example/tenant",
          @issuer <> "/",
          "https://ISSUER.example/tenant"
        ] do
      refute X509.matches_issuer?(leaf, other)
    end
  end

  test "matches only the issuer host against a DNS SAN when no URI SAN exists", ctx do
    leaf = validated_leaf(ctx.root, [{:dNSName, ~c"ISSUER.example"}])
    assert X509.matches_issuer?(leaf, @issuer)
    assert X509.matches_issuer?(leaf, "https://issuer.example:8443/another?query=1")
    refute X509.matches_issuer?(leaf, "https://other.example/tenant")
    refute X509.matches_issuer?(leaf, "https://issuer.example.evil/tenant")
  end

  test "a contradictory URI SAN cannot be rescued by a matching DNS SAN", ctx do
    leaf =
      validated_leaf(ctx.root, [{:uniformResourceIdentifier, ~c"https://other.example"}, {:dNSName, ~c"issuer.example"}])

    refute X509.matches_issuer?(leaf, @issuer)
  end

  test "URI SAN takes precedence even when DNS SAN differs", ctx do
    leaf =
      validated_leaf(ctx.root, [
        {:uniformResourceIdentifier, String.to_charlist(@issuer)},
        {:dNSName, ~c"other.example"}
      ])

    assert X509.matches_issuer?(leaf, @issuer)
  end

  test "any matching URI is sufficient but unrelated URI types still prevent DNS fallback", ctx do
    names = [{:uniformResourceIdentifier, ~c"urn:issuer:other"}, {:dNSName, ~c"issuer.example"}]
    refute X509.matches_issuer?(validated_leaf(ctx.root, names), @issuer)

    assert X509.matches_issuer?(
             validated_leaf(ctx.root, [{:uniformResourceIdentifier, String.to_charlist(@issuer)} | names]),
             @issuer
           )
  end

  test "no common-name fallback, wildcard, IP, or trailing-dot equivalence", ctx do
    assert {:ok, _} = X509.verify([ctx.root.cert], trusted_certificates: [ctx.root.cert])
    refute X509.matches_issuer?(ctx.root.cert, @issuer)

    for {name, issuer} <- [
          {~c"*.example", @issuer},
          {~c"issuer.example.", @issuer},
          {~c"127.0.0.1", "https://127.0.0.1"}
        ] do
      refute X509.matches_issuer?(validated_leaf(ctx.root, [{:dNSName, name}]), issuer)
    end
  end

  test "malformed inputs and non-HTTPS issuer identifiers fail closed", ctx do
    leaf = validated_leaf(ctx.root, [{:dNSName, ~c"issuer.example"}])

    for issuer <- [
          nil,
          42,
          %{},
          "",
          "issuer.example",
          "http://issuer.example",
          "urn:issuer:one",
          "https://issuer.example#fragment",
          "https://user@issuer.example",
          "https://issuer%2eexample",
          "https://issuer.example/%zz",
          "https://issuer.example\n",
          <<255>>
        ] do
      refute X509.matches_issuer?(leaf, issuer)
    end

    for certificate <- [nil, [], "", <<48, 128>>, :binary.copy("x", 65_537)] do
      refute X509.matches_issuer?(certificate, @issuer)
    end
  end

  defp validated_leaf(root, names) do
    issuer = Fixture.named_chain(root, names)
    assert {:ok, _} = X509.verify(issuer.chain, trusted_certificates: issuer.anchors)
    issuer.leaf
  end
end
