defmodule Attesto.CIBAStore do
  @moduledoc """
  Storage seam for the OpenID Connect CIBA grant
  (`urn:openid:params:grant-type:ciba`).

  Like `Attesto.DeviceCodeStore`, a CIBA authentication request is a *mutable*
  record that lives through a small state machine - `pending` → (`approved` |
  `denied`) → `consumed` - while the client polls the token endpoint (poll
  mode) or awaits a notification (ping mode) and the end-user authenticates on
  their authentication device. Every state transition is security-critical, so
  each MUST be a single atomic operation guarded on the current state, never an
  app-level read-then-write:

    * `approve/3` / `deny/2` move `pending` → `approved` / `denied` only - an
      already-decided or expired request is refused, so the user's decision is
      taken exactly once. Both return the transitioned record so the caller
      can deliver the ping-mode notification (CIBA Core §10.2 fires on ANY
      terminal outcome, approval or denial).
    * `poll/2` enforces the CIBA Core §7.3 minimum token-request interval as
      one atomic conditional update of `last_polled_at`, returning the record's
      current state in the same step (no separate read that could race an
      approval). The interval is a property of the stored record - it is the
      value the client was told in the authentication response - so `poll/2`
      reads it from the record, not from the caller.
    * `consume/2` moves `approved` → `consumed` only, so an approved
      authentication request mints exactly one token family even under
      concurrent token requests.

  The plaintext `auth_req_id` is never stored; only its
  `Attesto.Secret.hash/1`.

  ## Record shape

  A stored record is a map with:

    * `:auth_req_id_hash` - `Attesto.Secret.hash/1` of the `auth_req_id` (the
      lookup key).
    * `:data` - the issue-time context bound to the request: `%{client_id,
      delivery_mode, scope, acr_values, binding_message,
      client_notification_token, subject, resource, dpop_jkt}` - `subject` is
      the hint-resolved end-user the OP set out to authenticate (CIBA Core
      §7.1: identified BEFORE the `auth_req_id` is issued).
    * `:status` - `:pending` | `:approved` | `:denied` | `:consumed`.
    * `:subject` / `:acr` / `:auth_time` - bound at approval: the
      authenticated end-user, the Authentication Context Class Reference
      satisfied, and the unix time of authentication.
    * `:granted_scope` / `:granted_claims` - what the user actually authorized
      at approval (nil/absent until approved).
    * `:interval` - the minimum seconds between accepted polls (`0` disables
      enforcement; used for records that are consumed server-side).
    * `:expires_at` - absolute expiry, unix seconds.
    * `:last_polled_at` - unix seconds of the last accepted poll, or nil
      before the first poll.
  """

  @type auth_req_id_hash :: String.t()

  @typedoc "A stored CIBA authentication-request record (see the module docs)."
  @type entry :: %{
          required(:auth_req_id_hash) => auth_req_id_hash(),
          required(:data) => map(),
          required(:status) => :pending | :approved | :denied | :consumed,
          required(:interval) => non_neg_integer(),
          required(:expires_at) => non_neg_integer(),
          optional(:subject) => String.t() | nil,
          optional(:acr) => String.t() | nil,
          optional(:auth_time) => non_neg_integer() | nil,
          optional(:granted_scope) => [String.t()] | nil,
          optional(:granted_claims) => map() | nil,
          optional(:last_polled_at) => non_neg_integer() | nil
        }

  @doc """
  Persist a new `pending` authentication-request record. The
  `auth_req_id_hash` is the hash of a fresh 256-bit CSPRNG secret, so a key
  collision is a CSPRNG-grade impossibility and may raise.
  """
  @callback put(entry()) :: :ok

  @doc """
  Non-consuming read of the record for `auth_req_id_hash`, for the
  authentication-device UI to show what the user is approving. Returns
  `:error` when unknown.
  """
  @callback lookup(auth_req_id_hash()) :: {:ok, entry()} | :error

  @doc """
  Atomically move a `pending` request to `approved`, binding the resolved
  `:subject`, `:acr`, `:auth_time`, `:granted_scope`, and `:granted_claims`.
  MUST refuse a request that is not currently `pending`
  (`{:error, :already_decided}`), unknown (`{:error, :not_found}`), or expired
  at `opts.now` (`{:error, :expired}` - a decision on an expired request must
  not land). Returns the transitioned record. Implement as one guarded
  `UPDATE ... WHERE status = 'pending' AND expires_at > $now RETURNING`.
  """
  @callback approve(auth_req_id_hash(), approval :: map(), opts :: map()) ::
              {:ok, entry()} | {:error, :not_found | :already_decided | :expired}

  @doc """
  Atomically move a `pending` request to `denied`, so the client's next token
  request receives `access_denied`. Same guard/return contract as `approve/3`.
  """
  @callback deny(auth_req_id_hash(), opts :: map()) ::
              {:ok, entry()} | {:error, :not_found | :already_decided | :expired}

  @doc """
  Enforce the CIBA Core §7.3 minimum token-request interval and return the
  record's current state, in one atomic step. `opts` carries `:now` (unix
  seconds); the interval comes from the stored record's `:interval` (it is
  the value the client was told, so it must not drift per-call). Returns
  `{:ok, entry}` when the poll is accepted (updating `:last_polled_at` to
  `:now`), `{:error, :slow_down}` when the caller polled faster than the
  record's interval, or `:error` when the `auth_req_id` is unknown. Implement
  as one conditional `UPDATE ... SET last_polled_at = now WHERE
  auth_req_id_hash = $1 AND (last_polled_at IS NULL OR last_polled_at <= now -
  interval) RETURNING`, distinguishing unknown from slow_down by a follow-up
  existence check (both are non-mint outcomes, so that check is not a race).
  """
  @callback poll(auth_req_id_hash(), opts :: map()) ::
              {:ok, entry()} | {:error, :slow_down} | :error

  @doc """
  Atomically move an `approved`, unexpired request to `consumed` (single use),
  returning the record as it stood. MUST update only when `status =
  'approved' AND expires_at > opts.now`, so a second redemption of the same
  `auth_req_id` (concurrent or sequential) returns `:error` and a request that
  expires between the core's poll-time check and the consume cannot mint.
  Implement as one guarded `UPDATE ... SET status = 'consumed' WHERE status =
  'approved' AND expires_at > $now RETURNING`.
  """
  @callback consume(auth_req_id_hash(), opts :: map()) :: {:ok, entry()} | :error
end
