defmodule Attesto.Federation.EntityStatementTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Federation.EntityStatement
  alias Attesto.{JWS, Key, SigningAlg}
  alias Attesto.Test.Factory

  @entity "https://entity.example"
  @superior "https://superior.example"
  @now 1_800_000_000

  defmodule ProcessKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: Process.get({__MODULE__, :pem})

    @impl true
    def verification_pems, do: [signing_pem()]

    def install(pem), do: Process.put({__MODULE__, :pem}, pem)
  end

  test "builds and verifies a subordinate Entity Statement" do
    issuer_pem = Factory.ec_pem()
    subject_pem = Factory.ec_pem()

    jwt =
      EntityStatement.build(
        issuer_pem,
        %{
          "iss" => @superior,
          "sub" => @entity,
          "jwks" => jwks(subject_pem),
          "metadata" => %{"openid_provider" => %{"issuer" => @entity}},
          "metadata_policy" => %{
            "openid_provider" => %{"subject_types_supported" => %{"subset_of" => ["public", "pairwise"]}}
          },
          "constraints" => %{"max_path_length" => 0}
        },
        now: @now,
        lifetime_seconds: 600
      )

    assert {:ok, claims} = EntityStatement.verify(jwt, jwks(issuer_pem), now: @now)
    assert claims["iss"] == @superior
    assert claims["sub"] == @entity
    assert claims["iat"] == @now
    assert claims["exp"] == @now + 600
    assert claims["jwks"] == jwks(subject_pem)

    assert {:ok, %{"typ" => "entity-statement+jwt", "alg" => "ES256"}} =
             JWS.peek_json(jwt, :protected)
  end

  test "builds and verifies a self-signed Entity Configuration" do
    pem = Factory.ec_pem()

    jwt =
      EntityStatement.entity_configuration(pem, @entity,
        now: @now,
        authority_hints: [@superior],
        metadata: %{"openid_relying_party" => %{"redirect_uris" => ["https://entity.example/cb"]}},
        trust_marks: []
      )

    assert {:ok, claims} = EntityStatement.verify_self_signed(jwt, now: @now)
    assert claims["iss"] == @entity
    assert claims["sub"] == @entity
    assert claims["authority_hints"] == [@superior]
    assert claims["jwks"] == jwks(pem)
  end

  test "accepts an Attesto keystore module for signing" do
    pem = Factory.ec_pem()
    ProcessKeystore.install(pem)

    jwt = EntityStatement.entity_configuration(ProcessKeystore, @entity, now: @now)

    assert {:ok, %{"iss" => @entity, "sub" => @entity}} =
             EntityStatement.verify_self_signed(jwt, now: @now)
  end

  test "rejects a wrong key, an expired statement, and a wrong typ" do
    pem = Factory.ec_pem()
    wrong_pem = Factory.ec_pem()

    valid =
      EntityStatement.build(
        pem,
        %{"iss" => @superior, "sub" => @entity, "jwks" => jwks(wrong_pem)},
        now: @now
      )

    assert {:error, :invalid_signature} = EntityStatement.verify(valid, jwks(wrong_pem), now: @now)

    expired =
      EntityStatement.build(
        pem,
        %{
          "iss" => @superior,
          "sub" => @entity,
          "iat" => @now - 100,
          "exp" => @now - 1,
          "jwks" => jwks(wrong_pem)
        },
        now: @now
      )

    assert {:error, :expired} = EntityStatement.verify(expired, jwks(pem), now: @now)

    {:ok, claims} = JWS.peek_json(valid, :payload)

    wrong_typ =
      JWS.sign_compact(
        pem,
        %{"alg" => "ES256", "kid" => Key.kid(pem), "typ" => "JWT"},
        claims
      )

    assert {:error, :invalid_typ} = EntityStatement.verify(wrong_typ, jwks(pem), now: @now)
  end

  test "requires the metadata_policy claim to use all three levels" do
    issuer_pem = Factory.ec_pem()
    subject_pem = Factory.ec_pem()

    valid =
      EntityStatement.build(
        issuer_pem,
        %{"iss" => @superior, "sub" => @entity, "jwks" => jwks(subject_pem)},
        now: @now
      )

    {:ok, claims} = JWS.peek_json(valid, :payload)

    invalid =
      JWS.sign_compact(
        issuer_pem,
        %{"alg" => "ES256", "kid" => Key.kid(issuer_pem), "typ" => "entity-statement+jwt"},
        Map.put(claims, "metadata_policy", %{
          "grant_types" => %{"default" => ["authorization_code"]}
        })
      )

    assert {:error, :invalid_entity_statement} =
             EntityStatement.verify(invalid, jwks(issuer_pem), now: @now)
  end

  test "accepts and ignores an object-valued extension operator at the third level" do
    issuer_pem = Factory.ec_pem()
    subject_pem = Factory.ec_pem()
    extension_config = %{"configuration" => true}

    jwt =
      EntityStatement.build(
        issuer_pem,
        %{
          "iss" => @superior,
          "sub" => @entity,
          "jwks" => jwks(subject_pem),
          "metadata_policy" => %{
            "openid_provider" => %{
              "client_name" => %{"future_operator" => extension_config}
            }
          }
        },
        now: @now
      )

    assert {:ok, claims} = EntityStatement.verify(jwt, jwks(issuer_pem), now: @now)

    assert get_in(claims, ["metadata_policy", "openid_provider", "client_name", "future_operator"]) ==
             extension_config
  end

  test "rejects RSA verification keys below 2048 bits" do
    weak_signer = Factory.rsa_pem(1024)
    subject_pem = Factory.ec_pem()

    jwt =
      EntityStatement.build(
        weak_signer,
        %{"iss" => @superior, "sub" => @entity, "jwks" => jwks(subject_pem)},
        now: @now
      )

    assert {:error, :invalid_signature} = EntityStatement.verify(jwt, jwks(weak_signer), now: @now)
  end

  test "rejects an embedded RSA subject key below 2048 bits" do
    issuer_pem = Factory.ec_pem()
    strong_subject_pem = Factory.ec_pem()
    weak_subject_pem = Factory.rsa_pem(1024)

    valid =
      EntityStatement.build(
        issuer_pem,
        %{"iss" => @superior, "sub" => @entity, "jwks" => jwks(strong_subject_pem)},
        now: @now
      )

    {:ok, claims} = JWS.peek_json(valid, :payload)

    invalid =
      JWS.sign_compact(
        issuer_pem,
        %{"alg" => "ES256", "kid" => Key.kid(issuer_pem), "typ" => "entity-statement+jwt"},
        Map.put(claims, "jwks", jwks(weak_subject_pem))
      )

    assert {:error, :invalid_entity_statement} =
             EntityStatement.verify(invalid, jwks(issuer_pem), now: @now)
  end

  test "rejects oversized raw RSA parameters before algorithm inference" do
    signer = Factory.ec_pem()
    subject_pem = Factory.ec_pem()

    jwt =
      EntityStatement.build(
        signer,
        %{"iss" => @superior, "sub" => @entity, "jwks" => jwks(subject_pem)},
        now: @now
      )

    oversized_key = %{
      "kty" => "RSA",
      "kid" => Key.kid(signer),
      "n" => Base.url_encode64(:binary.copy(<<255>>, 1025), padding: false),
      "e" => "AQAB"
    }

    assert {:error, :invalid_signature} =
             EntityStatement.verify(jwt, %{"keys" => [oversized_key]}, now: @now)
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
