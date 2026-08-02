defmodule Attesto.CredentialResponseTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CredentialResponse

  @credential "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"

  test "wraps a single credential value" do
    assert CredentialResponse.build(@credential) == %{
             "credentials" => [%{"credential" => @credential}]
           }
  end

  test "emits multiple credentials in order" do
    assert CredentialResponse.build(["credential-1", "credential-2"]) == %{
             "credentials" => [
               %{"credential" => "credential-1"},
               %{"credential" => "credential-2"}
             ]
           }
  end

  test "passes a credential object through unchanged" do
    credential = %{"vct" => "IdentityCredential", "sub" => "did:example:123"}

    assert CredentialResponse.build(credential) == %{
             "credentials" => [%{"credential" => credential}]
           }
  end

  test "includes notification_id when supplied" do
    response = CredentialResponse.build(@credential, notification_id: "notification-123")

    assert response["notification_id"] == "notification-123"
  end

  test "omits notification_id when it is not supplied" do
    refute Map.has_key?(CredentialResponse.build(@credential), "notification_id")
    refute Map.has_key?(CredentialResponse.build(@credential, notification_id: nil), "notification_id")
  end

  test "rejects an empty or non-string notification_id" do
    for notification_id <- ["", 123, %{}] do
      assert_raise ArgumentError, ~r/:notification_id must be a non-empty string/, fn ->
        CredentialResponse.build(@credential, notification_id: notification_id)
      end
    end
  end

  test "rejects an empty credential list" do
    assert_raise ArgumentError, ~r/credentials must be non-empty/, fn ->
      CredentialResponse.build([])
    end
  end

  test "builds a deferred response" do
    assert CredentialResponse.deferred("transaction-123") == %{
             "transaction_id" => "transaction-123"
           }

    assert CredentialResponse.deferred("transaction-123", notification_id: "notification-123") == %{
             "transaction_id" => "transaction-123",
             "notification_id" => "notification-123"
           }
  end

  test "rejects a missing or empty transaction_id" do
    for transaction_id <- [nil, "", 123] do
      assert_raise ArgumentError, ~r/:transaction_id must be a non-empty string/, fn ->
        CredentialResponse.deferred(transaction_id)
      end
    end
  end

  test "never emits nonce response fields" do
    responses = [
      CredentialResponse.build(@credential),
      CredentialResponse.deferred("transaction-123")
    ]

    for response <- responses do
      refute Map.has_key?(response, "c_nonce")
      refute Map.has_key?(response, "c_nonce_expires_in")
    end
  end
end
