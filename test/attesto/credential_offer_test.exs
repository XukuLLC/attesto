defmodule Attesto.CredentialOfferTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CredentialOffer

  @issuer "https://issuer.example.com"
  @configuration_id "identity"
  @pre_auth "urn:ietf:params:oauth:grant-type:pre-authorized_code"

  defp required_opts do
    [credential_issuer: @issuer, credential_configuration_ids: [@configuration_id]]
  end

  test "builds a minimal offer and omits grants" do
    assert CredentialOffer.build(required_opts()) == %{
             "credential_issuer" => @issuer,
             "credential_configuration_ids" => [@configuration_id]
           }
  end

  test "normalizes a pre-authorized_code grant and tx_code" do
    offer =
      CredentialOffer.build(
        required_opts() ++
          [
            grants: %{
              pre_authorized_code: %{
                pre_authorized_code: "code-123",
                authorization_server: "https://auth.example.com",
                tx_code: %{
                  input_mode: "numeric",
                  length: 6,
                  description: "Enter the six-digit code"
                }
              }
            }
          ]
      )

    assert offer["grants"] == %{
             @pre_auth => %{
               "pre-authorized_code" => "code-123",
               "authorization_server" => "https://auth.example.com",
               "tx_code" => %{
                 "input_mode" => "numeric",
                 "length" => 6,
                 "description" => "Enter the six-digit code"
               }
             }
           }
  end

  test "drops nil optional grant values and retains an empty tx_code" do
    offer =
      CredentialOffer.build(
        required_opts() ++
          [
            grants: %{
              "pre-authorized_code" => %{
                "pre-authorized_code" => "code-123",
                authorization_server: nil,
                tx_code: %{input_mode: nil, length: nil, description: nil}
              }
            }
          ]
      )

    assert offer["grants"] == %{
             @pre_auth => %{
               "pre-authorized_code" => "code-123",
               "tx_code" => %{}
             }
           }
  end

  test "requires the pre-authorized_code value" do
    assert_raise ArgumentError, ~r/:pre-authorized_code must be a non-empty string/, fn ->
      CredentialOffer.build(
        required_opts() ++ [grants: %{pre_authorized_code: %{authorization_server: "https://auth.example.com"}}]
      )
    end
  end

  test "normalizes an authorization_code grant" do
    offer =
      CredentialOffer.build(
        required_opts() ++
          [grants: %{authorization_code: %{issuer_state: "state-123", authorization_server: nil}}]
      )

    assert offer["grants"] == %{
             "authorization_code" => %{"issuer_state" => "state-123"}
           }
  end

  test "normalizes both grant types together" do
    offer =
      CredentialOffer.build(
        required_opts() ++
          [
            grants: %{
              "authorization_code" => %{"issuer_state" => "state-123"},
              :"pre-authorized_code" => %{"pre-authorized_code" => "code-123"}
            }
          ]
      )

    assert Map.keys(offer["grants"]) |> Enum.sort() == ["authorization_code", @pre_auth]
    assert offer["grants"]["authorization_code"] == %{"issuer_state" => "state-123"}
    assert offer["grants"][@pre_auth] == %{"pre-authorized_code" => "code-123"}
  end

  test "rejects an empty or unknown grants map" do
    for grants <- [%{}, %{"unknown" => %{}}] do
      assert_raise ArgumentError, ~r/must contain at least one of/, fn ->
        CredentialOffer.build(required_opts() ++ [grants: grants])
      end
    end
  end

  test "rejects invalid tx_code fields" do
    assert_raise ArgumentError, ~r/:input_mode must be/, fn ->
      CredentialOffer.build(
        required_opts() ++
          [
            grants: %{
              pre_authorized_code: %{
                pre_authorized_code: "code-123",
                tx_code: %{input_mode: "otp"}
              }
            }
          ]
      )
    end

    assert_raise ArgumentError, ~r/:length must be a positive integer/, fn ->
      CredentialOffer.build(
        required_opts() ++
          [
            grants: %{
              pre_authorized_code: %{
                pre_authorized_code: "code-123",
                tx_code: %{length: 0}
              }
            }
          ]
      )
    end
  end

  test "requires a non-empty list of configuration ids" do
    for ids <- [[], nil, "identity", [""], ["identity", 123]] do
      assert_raise ArgumentError, ~r/:credential_configuration_ids must be a non-empty list/, fn ->
        CredentialOffer.build(Keyword.put(required_opts(), :credential_configuration_ids, ids))
      end
    end
  end

  test "accepts atom-keyed and string-keyed grant input" do
    atom_keyed =
      CredentialOffer.build(
        required_opts() ++
          [grants: %{pre_authorized_code: %{pre_authorized_code: "atom-code"}}]
      )

    string_keyed =
      CredentialOffer.build(
        required_opts() ++
          [
            grants: %{
              "pre-authorized_code" => %{"pre-authorized_code" => "string-code"}
            }
          ]
      )

    urn_keyed =
      CredentialOffer.build(required_opts() ++ [grants: %{@pre_auth => %{"pre-authorized_code" => "urn-code"}}])

    assert atom_keyed["grants"][@pre_auth]["pre-authorized_code"] == "atom-code"
    assert string_keyed["grants"][@pre_auth]["pre-authorized_code"] == "string-code"
    assert urn_keyed["grants"][@pre_auth]["pre-authorized_code"] == "urn-code"
  end

  test "to_query_value round-trips through JSON" do
    offer = CredentialOffer.build(required_opts())

    assert offer |> CredentialOffer.to_query_value() |> JSON.decode!() == offer
  end

  test "deep_link round-trips its credential_offer query parameter" do
    offer = CredentialOffer.build(required_opts())
    uri = CredentialOffer.deep_link(offer)
    %URI{scheme: "openid-credential-offer", query: query} = URI.parse(uri)

    assert URI.decode_query(query)["credential_offer"] |> JSON.decode!() == offer
  end

  test "deep_link_by_reference round-trips its credential_offer_uri query parameter" do
    reference = "https://issuer.example.com/offers/123?state=a%2Fb"
    uri = CredentialOffer.deep_link_by_reference(reference, scheme: "openid-credential-offer")
    %URI{scheme: "openid-credential-offer", query: query} = URI.parse(uri)

    assert URI.decode_query(query)["credential_offer_uri"] == reference
  end
end
