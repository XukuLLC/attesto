defmodule Attesto.PreAuthorizedCodeTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.PreAuthorizedCode
  alias Attesto.PreAuthorizedCodeStore.ETS, as: Store
  alias Attesto.Secret

  @now 1_000
  @racers 25

  setup do
    start_supervised!(Store)
    :ok
  end

  defp attrs(overrides \\ %{}) do
    Map.merge(
      %{
        subject: "usr_42",
        credential_configuration_ids: ["UniversityDegree_JWT"],
        authorized_scopes: ["openid"]
      },
      overrides
    )
  end

  defp race(fun) do
    1..@racers
    |> Enum.map(fn _ -> Task.async(fun) end)
    |> Task.await_many(5_000)
  end

  test "issue then redeem returns the bound grant context" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)

    assert {:ok, grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)

    assert grant == %{
             subject: "usr_42",
             credential_configuration_ids: ["UniversityDegree_JWT"],
             authorized_scopes: ["openid"]
           }
  end

  test "a code can be redeemed only once" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)
    assert {:ok, _grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
    assert {:error, :invalid_grant} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
  end

  test "an expired code returns expired" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), ttl: 0, now: @now)

    assert {:error, :expired} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
  end

  test "a matching transaction code redeems successfully" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:ok, _grant} = PreAuthorizedCode.redeem(Store, code, %{tx_code: "1234"}, now: @now)
  end

  test "a bound transaction code is required" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:error, :tx_code_required} = PreAuthorizedCode.redeem(Store, code, %{}, now: @now)
  end

  test "a wrong transaction code mismatches" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:error, :tx_code_mismatch} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "4321"}, now: @now)
  end

  test "an unexpected transaction code is rejected" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)

    assert {:error, :tx_code_unexpected} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "1234"}, now: @now)
  end

  test "the plaintext transaction code is never stored" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:ok, %{data: data}} = Store.get(Secret.hash(code))
    refute Map.has_key?(data, :tx_code)
    refute "1234" in Map.values(data)
    assert data.tx_code_hash == Secret.hash("1234")
  end

  test "an unknown code returns invalid grant" do
    assert {:error, :invalid_grant} = PreAuthorizedCode.redeem(Store, Secret.generate(), %{}, now: @now)
  end

  test "invalid attrs return invalid attrs" do
    assert {:error, :invalid_attrs} =
             PreAuthorizedCode.issue(Store, attrs() |> Map.delete(:subject), now: @now)

    assert {:error, :invalid_attrs} =
             PreAuthorizedCode.issue(Store, attrs(%{credential_configuration_ids: []}), now: @now)
  end

  test "a failed transaction-code check burns the code" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(%{tx_code: "1234"}), now: @now)

    assert {:error, :tx_code_mismatch} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "4321"}, now: @now)

    assert {:error, :invalid_grant} =
             PreAuthorizedCode.redeem(Store, code, %{tx_code: "1234"}, now: @now)
  end

  test "exactly one of 25 simultaneous redemptions wins" do
    {:ok, code} = PreAuthorizedCode.issue(Store, attrs(), now: @now)

    results = race(fn -> PreAuthorizedCode.redeem(Store, code, %{}, now: @now) end)

    winners = Enum.count(results, &match?({:ok, _}, &1))
    losers = Enum.count(results, &(&1 == {:error, :invalid_grant}))

    assert winners == 1
    assert losers == @racers - 1
  end
end
