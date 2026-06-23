defmodule Attesto.DeviceCodeStore do
  @moduledoc """
  Storage seam for the RFC 8628 device authorization grant.

  Unlike `Attesto.CodeStore` (a single-use code consumed by an atomic `take/1`),
  a device code is a *mutable* record that lives through a small state machine —
  `pending` → (`approved` | `denied`) → `consumed` — while the device polls the
  token endpoint and the user approves on a second device. Every state
  transition is security-critical, so each MUST be a single atomic operation
  guarded on the current state, never an app-level read-then-write:

    * `approve/2` / `deny/2` move `pending` → `approved` / `denied` only — an
      already-decided or expired code is refused, so the user's decision is
      taken exactly once.
    * `poll/2` enforces the RFC 8628 §3.5 minimum poll interval as one atomic
      conditional update of `last_polled_at`, returning the record's current
      state in the same step (no separate read that could race an approval).
    * `consume/2` moves `approved` → `consumed` only, so an approved device code
      mints exactly one token family even under concurrent polls.

  The plaintext `device_code` is never stored; only its `Attesto.Secret.hash/1`.
  The `user_code` is stored in its normalized form (see
  `Attesto.DeviceCode.normalize_user_code/2`).

  ## Record shape

  A stored record is a map with:

    * `:device_code_hash` - `Attesto.Secret.hash/1` of the device code (the poll
      lookup key).
    * `:user_code` - the normalized user code (the verification lookup key).
    * `:data` - the issue-time context bound to the code: `%{client_id, scope,
      resource, dpop_jkt}` (`scope`/`resource` lists; `dpop_jkt` optional).
    * `:status` - `:pending` | `:approved` | `:denied` | `:consumed`.
    * `:subject` - the approved resource owner (nil until approved).
    * `:granted_scope` / `:granted_claims` - what the user actually authorized at
      approval (nil/absent until approved).
    * `:expires_at` - absolute expiry, unix seconds.
    * `:last_polled_at` - unix seconds of the last accepted poll, or nil before
      the first poll.
  """

  @type user_code :: String.t()
  @type device_code_hash :: String.t()

  @typedoc "A stored device-code record (see the module docs)."
  @type entry :: %{
          required(:device_code_hash) => device_code_hash(),
          required(:user_code) => user_code(),
          required(:data) => map(),
          required(:status) => :pending | :approved | :denied | :consumed,
          required(:expires_at) => non_neg_integer(),
          optional(:subject) => String.t() | nil,
          optional(:granted_scope) => [String.t()] | nil,
          optional(:granted_claims) => map() | nil,
          optional(:last_polled_at) => non_neg_integer() | nil
        }

  @typedoc "The non-consuming verification-page view of a pending device code."
  @type pending_view :: %{
          required(:user_code) => user_code(),
          required(:client_id) => String.t() | nil,
          required(:scope) => [String.t()],
          required(:resource) => [String.t()],
          required(:status) => :pending | :approved | :denied | :consumed,
          required(:expires_at) => non_neg_integer()
        }

  @doc """
  Persist a new `pending` device-code record. Returns `{:error, :user_code_taken}`
  when the record's `user_code` collides with a live one (so `Attesto.DeviceCode`
  can retry with a fresh code); a `device_code_hash` collision is a CSPRNG-grade
  impossibility and may raise.
  """
  @callback put(entry()) :: :ok | {:error, :user_code_taken}

  @doc """
  Non-consuming read of the record for `user_code`, for the verification page to
  show the user what they are about to approve. Returns `:error` when unknown.
  """
  @callback lookup_user_code(user_code()) :: {:ok, pending_view()} | :error

  @doc """
  Atomically move a `pending` code to `approved`, binding the resolved
  `:subject`, `:granted_scope`, and `:granted_claims`. MUST refuse a code that
  is not currently `pending` (`{:error, :already_decided}`) or unknown
  (`{:error, :not_found}`); `{:error, :expired}` for an expired pending code.
  Implement as one guarded `UPDATE ... WHERE status = 'pending' RETURNING`.
  """
  @callback approve(user_code(), approval :: map()) ::
              :ok | {:error, :not_found | :already_decided | :expired}

  @doc """
  Atomically move a `pending` code to `denied`. Same guard/return contract as
  `approve/2`.
  """
  @callback deny(user_code()) :: :ok | {:error, :not_found | :already_decided | :expired}

  @doc """
  Enforce the RFC 8628 §3.5 minimum poll interval and return the code's current
  state, in one atomic step. `opts` carries `:now` (unix seconds) and
  `:interval` (seconds). Returns `{:ok, entry}` when the poll is accepted
  (updating `:last_polled_at` to `:now`), `{:error, :slow_down}` when the caller
  polled faster than `:interval`, or `:error` when the device code is unknown.
  Implement as one conditional `UPDATE ... SET last_polled_at = now WHERE
  device_code_hash = $1 AND (last_polled_at IS NULL OR last_polled_at <= now -
  interval) RETURNING`, distinguishing unknown from slow_down by a follow-up
  existence check (both are non-mint outcomes, so that check is not a race).
  """
  @callback poll(device_code_hash(), opts :: map()) ::
              {:ok, entry()} | {:error, :slow_down} | :error

  @doc """
  Atomically move an `approved` code to `consumed` (single use), returning the
  record as it stood. MUST update only when `status = 'approved'`, so a second
  redemption of the same device code (concurrent or sequential) returns
  `:error`. Implement as one guarded `UPDATE ... SET status = 'consumed' WHERE
  status = 'approved' RETURNING`.
  """
  @callback consume(device_code_hash(), opts :: map()) :: {:ok, entry()} | :error
end
