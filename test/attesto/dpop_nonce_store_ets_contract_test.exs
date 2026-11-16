defmodule Attesto.DPoPNonceStoreETSContractTest do
  @moduledoc false
  # Behaviour-contract conformance for the bundled single-node DPoP nonce
  # store, `Attesto.DPoP.NonceStore.ETS`.
  #
  # The `Attesto.DPoP.NonceStore` behaviour is the storage seam for
  # server-issued DPoP nonces (RFC 9449 §8): `issue/1` mints a fresh,
  # time-limited opaque nonce, and `valid?/1` reports whether a presented
  # nonce was issued by this store and is still live. A multi-node
  # deployment supplies its own implementation over a shared store, so the
  # invariants below are the ones ANY conforming `NonceStore` must hold,
  # not ETS-specific behaviour. They are written here against the ETS
  # reference the same way `code_store_ets_contract_test.exs` and
  # `refresh_store_ets_contract_test.exs` pin their stores; when the shared
  # `Attesto.NonceStoreContract.__using__` macro is extracted (mirroring
  # `Attesto.Test.CodeStoreContract` / `Attesto.RefreshStoreContract`), these
  # `test`s are its body and this file collapses to a one-line
  # `use Attesto.NonceStoreContract, store: Attesto.DPoP.NonceStore.ETS`.
  #
  # `Attesto.DPoP.NonceStore.ETS` is a named singleton GenServer, so the
  # store is `start_supervised!`-ed once per test and this module runs
  # `async: false`. We avoid `Process.sleep` for the expiry cases: a nonce's
  # `expires_at` is stamped against `System.system_time(:second)` and
  # `valid?/1` compares against that same clock, so we spin until the
  # store's own whole-second clock has advanced past the stamp.
  #
  # The end-to-end wiring of `validate/1` into `Attesto.DPoP.verify_proof/2`
  # and the `:nonce_check` engine seam live in `dpop_nonce_test.exs`; this
  # file is purely the storage-contract surface.
  use ExUnit.Case, async: false

  alias Attesto.DPoP.NonceStore
  alias Attesto.DPoP.NonceStore.ETS, as: Store

  setup do
    start_supervised!(Store)
    :ok
  end

  # ------------------------------------------------------------------
  # behaviour shape
  # ------------------------------------------------------------------

  describe "behaviour conformance" do
    test "the store declares the Attesto.DPoP.NonceStore behaviour" do
      behaviours =
        Store.module_info(:attributes)
        |> Keyword.get_values(:behaviour)
        |> List.flatten()

      assert NonceStore in behaviours
    end

    test "the store exports the issue/1 and valid?/1 callbacks" do
      # The two @callback functions every conforming NonceStore implements.
      assert function_exported?(Store, :issue, 1)
      assert function_exported?(Store, :valid?, 1)
    end
  end

  # ------------------------------------------------------------------
  # issue/1
  # ------------------------------------------------------------------

  describe "issue/1" do
    test "returns an opaque base64url string" do
      nonce = Store.issue(60)

      assert is_binary(nonce)
      # Opaque to the client, but the reference store hands out unpadded
      # base64url: only the URL-safe alphabet, never '+', '/', or '='.
      assert nonce =~ ~r/\A[A-Za-z0-9_-]+\z/
    end

    test "an issued nonce is immediately valid in its own store" do
      nonce = Store.issue(60)

      assert Store.valid?(nonce)
    end

    test "successive issues are unique (no nonce is handed out twice)" do
      # A reused nonce would let one challenge satisfy another client's
      # proof. Mint a batch and assert the set is fully distinct.
      nonces = for _ <- 1..200, do: Store.issue(60)

      assert length(Enum.uniq(nonces)) == length(nonces)
    end

    test "issue/0 mints a default-ttl nonce that is valid now" do
      # The arity-0 default-ttl clause is the common challenge path.
      nonce = Store.issue()

      assert is_binary(nonce)
      assert Store.valid?(nonce)
    end

    test "a non-positive ttl is a caller bug and raises (FunctionClauseError)" do
      # The contract is `ttl_seconds :: pos_integer()`; the guard rejects 0
      # and negatives rather than minting an already-dead nonce.
      assert_raise FunctionClauseError, fn -> Store.issue(0) end
      assert_raise FunctionClauseError, fn -> Store.issue(-5) end
    end
  end

  # ------------------------------------------------------------------
  # valid?/1 — liveness and isolation
  # ------------------------------------------------------------------

  describe "valid?/1" do
    test "is true for a live issued nonce, false for one this store never issued" do
      live = Store.issue(60)

      assert Store.valid?(live)
      refute Store.valid?("never-issued-by-this-store")
    end

    test "is false for a non-binary presented value rather than raising" do
      # A client-supplied claim may be any term (or nil when absent); the
      # store treats anything that is not a known binary nonce as not valid.
      refute Store.valid?(nil)
      refute Store.valid?(:not_a_nonce)
      refute Store.valid?(12_345)
    end

    test "validating one nonce does not consume or invalidate another" do
      a = Store.issue(60)
      b = Store.issue(60)

      # Nonces are independent: checking (or failing to find) one leaves the
      # rest untouched. valid? is also non-consuming — re-checking stays true.
      assert Store.valid?(a)
      refute Store.valid?("unrelated-unknown")
      assert Store.valid?(a)
      assert Store.valid?(b)
    end

    test "valid? is non-consuming: the same nonce reads valid repeatedly" do
      # Unlike a one-time code take, a nonce stays live for replays within
      # its ttl; expiry, not inspection, is what ends it.
      nonce = Store.issue(60)

      assert Store.valid?(nonce)
      assert Store.valid?(nonce)
      assert Store.valid?(nonce)
    end
  end

  # ------------------------------------------------------------------
  # ttl / expiry boundary
  # ------------------------------------------------------------------

  describe "expiry" do
    test "a nonce is live up to its ttl and not after it has elapsed" do
      # Issue with the smallest positive ttl, assert it starts live, then
      # spin (no Process.sleep) until the store's own clock has passed the
      # stamped expiry (now0 + 1) and assert it has flipped to invalid.
      nonce = Store.issue(1)
      assert Store.valid?(nonce)

      issued_at = System.system_time(:second)
      wait_until_clock_passes(issued_at + 1)

      refute Store.valid?(nonce)
    end

    test "validate/1 mirrors valid?/1 across the expiry boundary" do
      # validate/1 is the :nonce_check-shaped adapter: :ok while live,
      # {:error, :use_dpop_nonce} once expired. It must agree with valid?/1.
      nonce = Store.issue(1)
      assert :ok = Store.validate(nonce)

      issued_at = System.system_time(:second)
      wait_until_clock_passes(issued_at + 1)

      assert {:error, :use_dpop_nonce} = Store.validate(nonce)
    end
  end

  # ------------------------------------------------------------------
  # validate/1 — the :nonce_check adapter shape
  # ------------------------------------------------------------------

  describe "validate/1" do
    test "is :ok for a live nonce" do
      assert :ok = Store.validate(Store.issue(60))
    end

    test "is {:error, :use_dpop_nonce} for nil, unknown, and non-binary inputs" do
      # The nil case is the challenge path (client sent no nonce yet); the
      # unknown and non-binary cases are a forged or malformed claim. All
      # three collapse to the single RFC 9449 error the server returns to
      # trigger a DPoP-Nonce challenge.
      assert {:error, :use_dpop_nonce} = Store.validate(nil)
      assert {:error, :use_dpop_nonce} = Store.validate("client-made-this-up")
      assert {:error, :use_dpop_nonce} = Store.validate(:not_a_nonce)
    end
  end

  # ------------------------------------------------------------------
  # reset/0 — test-facing clear
  # ------------------------------------------------------------------

  describe "reset/0" do
    test "clears every issued nonce" do
      a = Store.issue(300)
      b = Store.issue(300)
      assert Store.valid?(a)
      assert Store.valid?(b)

      assert :ok = Store.reset()

      refute Store.valid?(a)
      refute Store.valid?(b)
      assert {:error, :use_dpop_nonce} = Store.validate(a)
    end

    test "the store still issues live nonces after a reset" do
      Store.issue(300)
      :ok = Store.reset()

      fresh = Store.issue(300)
      assert Store.valid?(fresh)
    end
  end

  # Spin until the store's clock (whole-second system time) has advanced
  # strictly past `target`, so any expiry stamp <= target is in the past.
  defp wait_until_clock_passes(target) do
    if System.system_time(:second) > target do
      :ok
    else
      wait_until_clock_passes(target)
    end
  end
end
