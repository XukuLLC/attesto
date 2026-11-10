defmodule Attesto.Federation.TrustChainTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Federation.{EntityStatement, TrustChain}
  alias Attesto.{Key, SigningAlg}
  alias Attesto.Test.Factory

  @leaf "https://leaf.example"
  @intermediate "https://intermediate.example"
  @anchor "https://anchor.example"
  @now 1_800_000_000

  test "validates a real P-256 chain and resolves superior metadata and policy" do
    fixture = chain_fixture()

    assert {:ok, result} =
             TrustChain.validate(fixture.chain, fixture.anchor_jwks,
               now: @now,
               trust_anchor: @anchor
             )

    assert result.trust_anchor == @anchor
    assert result.exp == @now + 300

    assert result.metadata == %{
             "openid_relying_party" => %{
               "contacts" => ["leaf@example", "anchor@example", "intermediate@example"],
               "grant_types" => ["authorization_code"],
               "redirect_uris" => ["https://leaf.example/cb"],
               "subject_type" => "pairwise",
               "token_endpoint_auth_method" => "private_key_jwt"
             }
           }
  end

  test "accepts a chain that ends with the Trust Anchor's Entity Configuration" do
    fixture = chain_fixture()
    anchor_configuration = EntityStatement.entity_configuration(fixture.anchor_pem, @anchor, now: @now, exp: @now + 200)

    assert {:ok, abbreviated} = TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now)

    assert {:ok, result} =
             TrustChain.validate(fixture.chain ++ [anchor_configuration], fixture.anchor_jwks,
               now: @now,
               trust_anchor: @anchor
             )

    assert result.trust_anchor == @anchor
    assert result.metadata == abbreviated.metadata
    assert result.exp == @now + 200
  end

  test "the Trust Anchor's Entity Configuration must verify with the anchor keys and name the last issuer" do
    fixture = chain_fixture()

    other_entity = EntityStatement.entity_configuration(fixture.anchor_pem, "https://other-anchor.example", now: @now)
    other_key = EntityStatement.entity_configuration(Factory.ec_pem(), @anchor, now: @now)

    assert {:error, :broken_trust_chain} =
             TrustChain.validate(fixture.chain ++ [other_entity], fixture.anchor_jwks, now: @now)

    assert {:error, :invalid_signature} =
             TrustChain.validate(fixture.chain ++ [other_key], fixture.anchor_jwks, now: @now)
  end

  test "rejects a broken signature link" do
    fixture = chain_fixture()
    rogue_pem = Factory.ec_pem()

    broken_intermediate =
      subordinate_statement(
        rogue_pem,
        @intermediate,
        @leaf,
        fixture.leaf_jwks,
        @now + 400,
        lower_policy()
      )

    [leaf, _intermediate, anchor] = fixture.chain

    assert {:error, :invalid_signature} =
             TrustChain.validate([leaf, broken_intermediate, anchor], fixture.anchor_jwks, now: @now)
  end

  test "rejects an expired link" do
    fixture = chain_fixture()

    expired_intermediate =
      EntityStatement.build(
        fixture.intermediate_pem,
        %{
          "iss" => @intermediate,
          "sub" => @leaf,
          "iat" => @now - 100,
          "exp" => @now - 1,
          "jwks" => fixture.leaf_jwks,
          "metadata_policy" => lower_policy()
        },
        now: @now
      )

    [leaf, _intermediate, anchor] = fixture.chain

    assert {:error, :expired} =
             TrustChain.validate([leaf, expired_intermediate, anchor], fixture.anchor_jwks, now: @now)
  end

  test "rejects an unmet maximum path length constraint" do
    fixture = chain_fixture(anchor_constraints: %{"max_path_length" => 0})

    assert {:error, :constraint_violation} =
             TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now)
  end

  test "requires the leaf authority_hints to name its immediate superior" do
    missing = chain_fixture(authority_hints: :absent)
    mismatched = chain_fixture(authority_hints: ["https://other-superior.example"])

    assert {:error, :broken_trust_chain} =
             TrustChain.validate(missing.chain, missing.anchor_jwks, now: @now)

    assert {:error, :broken_trust_chain} =
             TrustChain.validate(mismatched.chain, mismatched.anchor_jwks, now: @now)
  end

  test "enforces permitted and excluded naming constraints on every subordinate entity" do
    permitted =
      chain_fixture(
        anchor_constraints: %{
          "max_path_length" => 1,
          "naming_constraints" => %{"permitted" => [".example"]}
        }
      )

    assert {:ok, _result} = TrustChain.validate(permitted.chain, permitted.anchor_jwks, now: @now)

    excluded =
      chain_fixture(
        anchor_constraints: %{
          "max_path_length" => 1,
          "naming_constraints" => %{
            "permitted" => [".example"],
            "excluded" => ["leaf.example"]
          }
        }
      )

    assert {:error, :constraint_violation} =
             TrustChain.validate(excluded.chain, excluded.anchor_jwks, now: @now)

    # OpenID Federation 1.0 §3.1.3 applies constraints to the subject of the
    # Subordinate Statement as well as every Entity beneath it. A bare domain
    # is an exact-host constraint, so permitting only the leaf still excludes
    # the intermediate named by the anchor's statement.
    exact_only =
      chain_fixture(
        anchor_constraints: %{
          "max_path_length" => 1,
          "naming_constraints" => %{"permitted" => ["leaf.example"]}
        }
      )

    assert {:error, :constraint_violation} =
             TrustChain.validate(exact_only.chain, exact_only.anchor_jwks, now: @now)

    apex_is_not_a_subdomain =
      chain_fixture(
        anchor_constraints: %{
          "max_path_length" => 1,
          "naming_constraints" => %{
            "permitted" => [".leaf.example", "intermediate.example"]
          }
        }
      )

    assert {:error, :constraint_violation} =
             TrustChain.validate(apex_is_not_a_subdomain.chain, apex_is_not_a_subdomain.anchor_jwks, now: @now)
  end

  test "a trailing-dot host cannot step around naming constraints" do
    # DNS treats `intermediate.example.` and `intermediate.example` as one name;
    # the constraint check must too, or an `excluded` entry is one byte away
    # from useless.
    dotted_entity =
      chain_fixture(
        intermediate_entity: "https://intermediate.example.",
        authority_hints: ["https://intermediate.example."],
        anchor_constraints: %{
          "max_path_length" => 1,
          "naming_constraints" => %{
            "permitted" => [".example"],
            "excluded" => ["intermediate.example"]
          }
        }
      )

    assert {:error, :constraint_violation} =
             TrustChain.validate(dotted_entity.chain, dotted_entity.anchor_jwks, now: @now)

    dotted_constraint =
      chain_fixture(
        anchor_constraints: %{
          "max_path_length" => 1,
          "naming_constraints" => %{"permitted" => [".example"], "excluded" => ["leaf.example."]}
        }
      )

    assert {:error, :constraint_violation} =
             TrustChain.validate(dotted_constraint.chain, dotted_constraint.anchor_jwks, now: @now)
  end

  test "a host that is not an LDH name satisfies no naming constraint" do
    # `intermediate.b%61d.example` names `intermediate.bad.example` to HTTP
    # clients that decode the host, and `evil.test%2F.example` ends in
    # `.example` only as a string.
    for {entity, naming_constraints} <- [
          {"https://intermediate.bad%2eexample", %{"excluded" => [".bad.example"]}},
          {"https://intermediate%2Ebad.example", %{"excluded" => [".bad.example"]}},
          {"https://intermediate.b%61d.example", %{"excluded" => [".bad.example"]}},
          {"https://b%61d.example", %{"excluded" => ["bad.example"]}},
          {"https://evil.test%2F.example", %{"permitted" => [".example"]}},
          {"https://evil.test,.example", %{"permitted" => [".example"]}}
        ] do
      fixture =
        chain_fixture(
          intermediate_entity: entity,
          authority_hints: [entity],
          anchor_constraints: %{"max_path_length" => 1, "naming_constraints" => naming_constraints}
        )

      assert {:error, :constraint_violation} =
               TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now),
             "expected #{entity} to fail #{inspect(naming_constraints)}"
    end

    for {entity, naming_constraints} <- [
          {"https://INTERMEDIATE.Example", %{"permitted" => [".example"], "excluded" => [".bad.example"]}},
          {"https://intermediate.example", %{"excluded" => [".bad.example"]}}
        ] do
      fixture =
        chain_fixture(
          intermediate_entity: entity,
          authority_hints: [entity],
          anchor_constraints: %{"max_path_length" => 1, "naming_constraints" => naming_constraints}
        )

      assert {:ok, _result} = TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now)
    end
  end

  test "applies an intermediate statement's naming constraints to its leaf subject" do
    fixture =
      chain_fixture(
        intermediate_constraints: %{
          "naming_constraints" => %{"permitted" => ["other.example"]}
        }
      )

    assert {:error, :constraint_violation} =
             TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now)
  end

  test "fails closed on malformed naming constraints while ignoring unrelated extensions" do
    malformed =
      chain_fixture(anchor_constraints: %{"naming_constraints" => %{"permitted" => []}})

    assert {:error, :constraint_violation} =
             TrustChain.validate(malformed.chain, malformed.anchor_jwks, now: @now)

    extension = chain_fixture(anchor_constraints: %{"future_constraint" => %{"mode" => "strict"}})
    assert {:ok, _result} = TrustChain.validate(extension.chain, extension.anchor_jwks, now: @now)
  end

  test "a present null constraint is malformed, not an omitted restriction" do
    for name <- ~w(max_path_length naming_constraints allowed_entity_types) do
      fixture = chain_fixture(anchor_constraints: %{name => nil})

      assert {:error, :constraint_violation} =
               TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now),
             "expected a null #{name} to be refused"
    end

    omitted = chain_fixture(anchor_constraints: %{})
    assert {:ok, _result} = TrustChain.validate(omitted.chain, omitted.anchor_jwks, now: @now)
  end

  test "a null value operator in a signed policy removes the parameter" do
    fixture = chain_fixture(anchor_policy: %{"openid_relying_party" => %{"redirect_uris" => %{"value" => nil}}})

    assert {:ok, result} = TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now)
    refute Map.has_key?(result.metadata["openid_relying_party"], "redirect_uris")
  end

  test "fails closed when policy forbids leaf metadata" do
    forbidden_policy = %{
      "openid_relying_party" => %{
        "token_endpoint_auth_method" => %{"one_of" => ["tls_client_auth"]}
      }
    }

    fixture = chain_fixture(anchor_policy: forbidden_policy)

    assert {:error, :policy_error} =
             TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now)
  end

  test "bounds chain length before signature verification" do
    fixture = chain_fixture()

    assert {:error, :invalid_trust_chain} =
             TrustChain.validate(fixture.chain, fixture.anchor_jwks,
               now: @now,
               max_chain_length: 2
             )

    assert_raise ArgumentError, fn ->
      TrustChain.validate(fixture.chain, fixture.anchor_jwks, max_chain_length: 0)
    end
  end

  test "rejects repeated entity identifiers as a cycle" do
    fixture = chain_fixture(anchor_entity: @leaf)
    assert {:error, :broken_trust_chain} = TrustChain.validate(fixture.chain, fixture.anchor_jwks, now: @now)
  end

  defp chain_fixture(overrides \\ []) do
    leaf_pem = Factory.ec_pem()
    intermediate_pem = Factory.ec_pem()
    anchor_pem = Factory.ec_pem()
    leaf_jwks = jwks(leaf_pem)
    intermediate_jwks = jwks(intermediate_pem)
    anchor_jwks = jwks(anchor_pem)

    leaf_options = [
      now: @now,
      exp: @now + 300,
      metadata: %{
        "openid_relying_party" => %{
          "contacts" => ["leaf@example"],
          "redirect_uris" => ["https://leaf.example/cb"],
          "token_endpoint_auth_method" => "private_key_jwt"
        },
        "oauth_client" => %{"client_name" => "removed by allowed_entity_types"}
      }
    ]

    leaf_options =
      case Keyword.get(overrides, :authority_hints, [@intermediate]) do
        :absent -> leaf_options
        hints -> Keyword.put(leaf_options, :authority_hints, hints)
      end

    leaf = EntityStatement.entity_configuration(leaf_pem, @leaf, leaf_options)

    intermediate_entity = Keyword.get(overrides, :intermediate_entity, @intermediate)

    intermediate =
      subordinate_statement(
        intermediate_pem,
        intermediate_entity,
        @leaf,
        leaf_jwks,
        @now + 400,
        lower_policy(),
        Keyword.get(overrides, :intermediate_constraints)
      )

    anchor_policy = Keyword.get(overrides, :anchor_policy, higher_policy())

    anchor_constraints =
      Keyword.get(overrides, :anchor_constraints, %{
        "max_path_length" => 1,
        "allowed_entity_types" => ["openid_relying_party"]
      })

    anchor_entity = Keyword.get(overrides, :anchor_entity, @anchor)

    anchor =
      EntityStatement.build(
        anchor_pem,
        %{
          "iss" => anchor_entity,
          "sub" => intermediate_entity,
          "jwks" => intermediate_jwks,
          "metadata_policy" => anchor_policy,
          "constraints" => anchor_constraints
        },
        now: @now,
        exp: @now + 500
      )

    %{
      chain: [leaf, intermediate, anchor],
      leaf_jwks: leaf_jwks,
      intermediate_pem: intermediate_pem,
      anchor_pem: anchor_pem,
      anchor_jwks: anchor_jwks
    }
  end

  defp subordinate_statement(pem, issuer, subject, subject_jwks, exp, policy, constraints \\ nil) do
    claims =
      %{
        "iss" => issuer,
        "sub" => subject,
        "jwks" => subject_jwks,
        "metadata_policy" => policy
      }
      |> maybe_put("constraints", constraints)

    EntityStatement.build(
      pem,
      claims,
      now: @now,
      exp: exp
    )
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp higher_policy do
    %{
      "openid_relying_party" => %{
        "contacts" => %{"add" => ["anchor@example"]},
        "grant_types" => %{"subset_of" => ["authorization_code", "refresh_token"]},
        "subject_type" => %{"value" => "pairwise"},
        "token_endpoint_auth_method" => %{"one_of" => ["private_key_jwt", "tls_client_auth"]}
      }
    }
  end

  defp lower_policy do
    %{
      "openid_relying_party" => %{
        "contacts" => %{"add" => ["intermediate@example"]},
        "grant_types" => %{"default" => ["authorization_code"]}
      }
    }
  end

  defp jwks(pem) do
    jwk = Key.jwk(pem)
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)

    %{
      "keys" => [
        Map.merge(public, %{
          "alg" => SigningAlg.infer(jwk),
          "kid" => Key.kid(pem)
        })
      ]
    }
  end
end
