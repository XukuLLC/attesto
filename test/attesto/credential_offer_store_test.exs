defmodule Attesto.CredentialOfferStoreTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.CredentialOfferStore
  alias Attesto.CredentialOfferStore.ETS, as: Store

  setup do
    start_supervised!(Store)
    :ok
  end

  defp entry(id, offer, expires_at \\ nil) do
    %{id: id, offer: offer, expires_at: expires_at || System.system_time(:second) + 60}
  end

  test "declares and implements the credential-offer store behaviour" do
    behaviours =
      Store.module_info(:attributes)
      |> Keyword.get_values(:behaviour)
      |> List.flatten()

    assert CredentialOfferStore in behaviours
    assert function_exported?(Store, :put, 1)
    assert function_exported?(Store, :fetch, 1)
  end

  test "put then fetch returns the offer" do
    offer = %{credential_issuer: "https://issuer.example", credential_configuration_ids: ["UniversityDegree_JWT"]}
    assert :ok = Store.put(entry("offer-1", offer))
    assert {:ok, ^offer} = Store.fetch("offer-1")
  end

  test "an unknown id returns :error" do
    assert :error = Store.fetch("never-stored")
  end

  test "an expired entry returns :error" do
    offer = %{credential_issuer: "https://issuer.example"}
    assert :ok = Store.put(entry("expired", offer, System.system_time(:second) - 1))

    assert :error = Store.fetch("expired")
  end

  test "fetch is non-consuming" do
    offer = %{credential_issuer: "https://issuer.example"}
    assert :ok = Store.put(entry("reusable", offer))

    assert {:ok, ^offer} = Store.fetch("reusable")
    assert {:ok, ^offer} = Store.fetch("reusable")
  end
end
