defmodule Attesto.PublicAPICompatibilityTest do
  use ExUnit.Case, async: true

  alias Attesto.IDToken
  alias Attesto.LogoutSessionStore
  alias Attesto.SdJwt
  alias Attesto.Token

  test "2.x token and disclosure helpers remain callable" do
    assert IDToken.header_typ() == "JWT"
    assert Token.typ_values() == ["access", "refresh"]

    disclosure = SdJwt.array_disclosure("salt", %{"claim" => true})
    assert {:ok, encoded} = Base.url_decode64(disclosure, padding: false)
    assert JSON.decode!(encoded) == ["salt", %{"claim" => true}]
  end

  test "2.x logout stores retain their original required callbacks" do
    callbacks = MapSet.new(LogoutSessionStore.behaviour_info(:callbacks))
    optional = MapSet.new(LogoutSessionStore.behaviour_info(:optional_callbacks))

    assert MapSet.subset?(MapSet.new(record: 1, targets: 1, delete: 1, take_targets: 1), callbacks)
    assert MapSet.disjoint?(MapSet.new(targets: 1, delete: 1, take_targets: 1), optional)

    assert optional ==
             MapSet.new(lease_targets: 4, acknowledge_targets: 2, release_targets: 2)
  end
end
