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

  defp chain_fixture(overrides \\ []) do
    leaf_pem = Factory.ec_pem()
    intermediate_pem = Factory.ec_pem()
    anchor_pem = Factory.ec_pem()
    leaf_jwks = jwks(leaf_pem)
    intermediate_jwks = jwks(intermediate_pem)
    anchor_jwks = jwks(anchor_pem)

    leaf =
      EntityStatement.entity_configuration(leaf_pem, @leaf,
        now: @now,
        exp: @now + 300,
        authority_hints: [@intermediate],
        metadata: %{
          "openid_relying_party" => %{
            "contacts" => ["leaf@example"],
            "redirect_uris" => ["https://leaf.example/cb"],
            "token_endpoint_auth_method" => "private_key_jwt"
          },
          "oauth_client" => %{"client_name" => "removed by allowed_entity_types"}
        }
      )

    intermediate =
      subordinate_statement(
        intermediate_pem,
        @intermediate,
        @leaf,
        leaf_jwks,
        @now + 400,
        lower_policy()
      )

    anchor_policy = Keyword.get(overrides, :anchor_policy, higher_policy())

    anchor_constraints =
      Keyword.get(overrides, :anchor_constraints, %{
        "max_path_length" => 1,
        "allowed_entity_types" => ["openid_relying_party"]
      })

    anchor =
      EntityStatement.build(
        anchor_pem,
        %{
          "iss" => @anchor,
          "sub" => @intermediate,
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
      anchor_jwks: anchor_jwks
    }
  end

  defp subordinate_statement(pem, issuer, subject, subject_jwks, exp, policy) do
    EntityStatement.build(
      pem,
      %{
        "iss" => issuer,
        "sub" => subject,
        "jwks" => subject_jwks,
        "metadata_policy" => policy
      },
      now: @now,
      exp: exp
    )
  end

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
