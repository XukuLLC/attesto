defmodule Attesto.DeviceCodeTest do
  use ExUnit.Case, async: false

  alias Attesto.DeviceCode
  alias Attesto.DeviceCode.Grant
  alias Attesto.DeviceCodeStore.ETS, as: Store

  @now 1_700_000_000

  setup do
    start_supervised!(Store)
    Store.reset()
    :ok
  end

  defp issue(attrs \\ %{}, opts \\ []) do
    attrs = Map.merge(%{client_id: "cli-1", scope: ["read"]}, attrs)
    {:ok, issued} = DeviceCode.issue(Store, attrs, Keyword.put_new(opts, :now, @now))
    issued
  end

  describe "issue/3" do
    test "returns a device code and a display-formatted user code" do
      %{device_code: dc, user_code: uc} = issue()
      assert is_binary(dc) and byte_size(dc) > 20
      # Display form: BCDF-GHJK (hyphenated groups of 4 from the base-20 alphabet).
      assert uc =~ ~r/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/
    end

    test "rejects a missing client_id" do
      assert {:error, :invalid_client_id} = DeviceCode.issue(Store, %{scope: ["read"]})
    end

    test "retries on a user_code collision and gives up after the bounded retries" do
      # A store that always reports the user_code as taken exhausts the retries.
      defmodule AlwaysTakenStore do
        def put(_record), do: {:error, :user_code_taken}
      end

      assert {:error, :user_code_unavailable} =
               DeviceCode.issue(AlwaysTakenStore, %{client_id: "cli-1"})
    end

    test "generated user codes are well-formed and varied (CSPRNG)" do
      codes = for _ <- 1..50, do: DeviceCode.generate_user_code()
      assert Enum.all?(codes, &(&1 =~ ~r/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/))
      # 50 draws from ~34.6 bits should be unique with overwhelming probability.
      assert length(Enum.uniq(codes)) == 50
    end
  end

  describe "user_code normalization (fail-closed)" do
    test "normalizes case + separators and validates the charset/length" do
      assert {:ok, "BCDFGHJK"} = DeviceCode.normalize_user_code("bcdf-ghjk")
      assert {:ok, "BCDFGHJK"} = DeviceCode.normalize_user_code("BCDF GHJK")
    end

    test "rejects out-of-alphabet, wrong-length, and ambiguous characters" do
      for bad <- ["BCDF-GHJ", "BCDFGHJKL", "AEIO-UEIO", "BCDF-GH0K", "BCDF-GH1K", ""] do
        assert {:error, :invalid_user_code} = DeviceCode.normalize_user_code(bad), "expected reject for #{inspect(bad)}"
      end
    end
  end

  describe "redeem/4 — RFC 8628 §3.5 state machine" do
    test "pending yields authorization_pending; approval then yields the grant; reuse is invalid_grant" do
      %{device_code: dc, user_code: uc} = issue()

      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 1)

      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1", scope: ["read"], claims: %{"acr" => "phr"}})

      assert {:ok, %Grant{client_id: "cli-1", subject: "usr_1", scope: ["read"], claims: %{"acr" => "phr"}}} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 10)

      # Single-use: a second redemption of the consumed code is invalid_grant.
      assert {:error, :invalid_grant} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 20)
    end

    test "deny yields access_denied" do
      %{device_code: dc, user_code: uc} = issue()
      assert :ok = DeviceCode.deny(Store, uc)
      assert {:error, :access_denied} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 10)
    end

    test "an expired code yields expired_token, even after approval (expiry wins)" do
      %{device_code: dc, user_code: uc} = issue(%{}, ttl: 600)
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"})
      assert {:error, :expired_token} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 601)
    end

    test "polling faster than the interval yields slow_down" do
      %{device_code: dc} = issue()
      # First poll accepted (pending).
      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 1, interval: 5)

      # Immediate re-poll within the interval.
      assert {:error, :slow_down} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 2, interval: 5)
      # After the interval, polling resumes.
      assert {:error, :authorization_pending} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 7, interval: 5)
    end

    test "an unknown device code is invalid_grant" do
      assert {:error, :invalid_grant} = DeviceCode.redeem(Store, "never-issued", %{client_id: "cli-1"}, now: @now)
    end

    test "a client_id mismatch is invalid_grant and does not burn the code" do
      %{device_code: dc, user_code: uc} = issue()
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"})

      assert {:error, :invalid_grant} = DeviceCode.redeem(Store, dc, %{client_id: "wrong"}, now: @now + 10, interval: 0)
      # The correct client still redeems (the mismatch did not consume it).
      assert {:ok, %Grant{}} = DeviceCode.redeem(Store, dc, %{client_id: "cli-1"}, now: @now + 11, interval: 0)
    end
  end

  describe "DPoP holder-of-key pre-binding (RFC 9449 §10)" do
    test "a code bound to a dpop_jkt redeems only with the matching proof key" do
      %{device_code: dc, user_code: uc} = issue(%{dpop_jkt: "jkt-abc"})
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"})

      assert {:error, :invalid_grant} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1", dpop_jkt: "jkt-wrong"}, now: @now + 10, interval: 0)

      assert {:ok, %Grant{dpop_jkt: "jkt-abc"}} =
               DeviceCode.redeem(Store, dc, %{client_id: "cli-1", dpop_jkt: "jkt-abc"}, now: @now + 11, interval: 0)
    end
  end

  describe "approve/deny guards" do
    test "approving a non-pending code is refused (decided once)" do
      %{user_code: uc} = issue()
      assert :ok = DeviceCode.approve(Store, uc, %{subject: "usr_1"})
      assert {:error, :already_decided} = DeviceCode.approve(Store, uc, %{subject: "usr_2"})
      assert {:error, :already_decided} = DeviceCode.deny(Store, uc)
    end

    test "approve requires a subject" do
      %{user_code: uc} = issue()
      assert {:error, :invalid_subject} = DeviceCode.approve(Store, uc, %{})
    end

    test "an unknown user_code is not_found; a malformed one is invalid_user_code" do
      assert {:error, :not_found} = DeviceCode.approve(Store, "BCDF-GHJK", %{subject: "usr_1"})
      assert {:error, :invalid_user_code} = DeviceCode.approve(Store, "nope", %{subject: "usr_1"})
    end
  end

  describe "lookup/2 (verification page view)" do
    test "returns the pending view for the user to confirm" do
      %{user_code: uc} = issue(%{scope: ["read", "write"]})
      assert {:ok, view} = DeviceCode.lookup(Store, uc)
      assert view.client_id == "cli-1"
      assert view.scope == ["read", "write"]
      assert view.status == :pending
    end

    test "malformed input is rejected before the store lookup" do
      assert {:error, :invalid_user_code} = DeviceCode.lookup(Store, "bad")
    end
  end
end
