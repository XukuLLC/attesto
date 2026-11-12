defmodule Attesto.RevocationCriteriaTest do
  use ExUnit.Case, async: true

  alias Attesto.RevocationCriteria

  @data %{subject: "usr_1", client_id: "client_a", claims: %{"sid" => "s1", "host.session" => "h1"}}

  describe "new!/1" do
    test "fills absent keys with nil and defaults the sid claim" do
      assert RevocationCriteria.new!(subject: "usr_1") ==
               %{subject: "usr_1", client_id: nil, sid: nil, sid_claim: "sid"}

      assert %{sid: "s1", sid_claim: "host.session"} = RevocationCriteria.new!(sid: "s1", sid_claim: "host.session")
    end

    test "refuses an empty or unusable selection" do
      for invalid <- [
            [],
            [sid_claim: "sid"],
            [subject: ""],
            [subject: nil],
            [subject: :usr_1],
            [subject: "usr_1", subject: "usr_2"],
            [tenant: "t1"],
            [subject: "usr_1", tenant: "t1"],
            %{subject: "usr_1"},
            ["usr_1"],
            nil
          ] do
        assert_raise ArgumentError, ~r/revocation criteria must be a keyword list/, fn ->
          RevocationCriteria.new!(invalid)
        end
      end
    end
  end

  describe "match?/2" do
    test "every given key must match" do
      match? = fn criteria -> criteria |> RevocationCriteria.new!() |> RevocationCriteria.match?(@data) end

      assert match?.(subject: "usr_1")
      assert match?.(client_id: "client_a")
      assert match?.(sid: "s1")
      assert match?.(subject: "usr_1", client_id: "client_a", sid: "s1")
      assert match?.(sid: "h1", sid_claim: "host.session")

      refute match?.(subject: "usr_2")
      refute match?.(subject: "usr_1", client_id: "client_b")
      refute match?.(sid: "h1")
      refute match?.(sid: "s1", sid_claim: "host.session")
    end

    test "a grant with no claims or no client never matches on those keys" do
      criteria = RevocationCriteria.new!(sid: "s1")
      refute RevocationCriteria.match?(criteria, %{subject: "usr_1", client_id: nil})
      refute RevocationCriteria.match?(criteria, %{subject: "usr_1", claims: %{}})

      refute RevocationCriteria.match?(RevocationCriteria.new!(client_id: "client_a"), %{
               subject: "usr_1",
               client_id: nil
             })
    end
  end
end
