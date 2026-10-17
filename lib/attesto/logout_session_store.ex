defmodule Attesto.LogoutSessionStore do
  @moduledoc """
  Storage seam for OpenID Connect Back-Channel Logout 1.0 and Front-Channel
  Logout 1.0.

  Both logout mechanisms require the OP to remember which Relying Parties hold
  a session for the End-User so it can notify them when that session ends:
  Back-Channel Logout by POSTing a signed `logout_token` to the RP's
  `backchannel_logout_uri` (Back-Channel Logout 1.0 §2.5), Front-Channel
  Logout by rendering the RP's `frontchannel_logout_uri` in an iframe on the
  logout page (Front-Channel Logout 1.0 §3). This behaviour is that memory: a
  row is recorded each time an ID Token is minted to a logout-capable client
  (the OP is the party that mints those tokens, so it is the natural place to
  record the binding), and enumerated when the end-session endpoint fires.

  This is **not** the browser login session — attesto never models that; the
  host owns login and supplies the `sid`. This store only persists the OP-side
  `(sid, client_id) -> logout URIs` delivery map, exactly as
  `Attesto.RefreshStore` persists issued refresh families. Killing the actual
  login state remains a host concern (the end-session controller's
  `:terminate_session` callback).

  ## Record shape

  A stored record (`record/1` input) is a map with:

    * `:sid` - the session id (the value asserted in the ID Token's `sid`
      claim). The per-session key the fan-out matches on.
    * `:subject` - the `sub` the session authenticated. The per-subject key,
      used when logout is requested without a `sid`.
    * `:client_id` - the Relying Party that received the ID Token.
    * `:backchannel_logout_uri` - where the `logout_token` is POSTed, or `nil`
      for an RP that is not back-channel-logout capable.
    * `:session_required` - the client's `backchannel_logout_session_required`
      (whether its `logout_token` MUST carry `sid`).
    * `:frontchannel_logout_uri` - the RP URL the logout page renders in an
      iframe (Front-Channel Logout 1.0 §2), or `nil` for an RP that is not
      front-channel-logout capable.
    * `:frontchannel_session_required` - the client's
      `frontchannel_logout_session_required` (whether the rendered URI must
      carry `iss` and `sid` query parameters).
    * `:expires_at` - absolute expiry, unix seconds (so abandoned sessions are
      swept; mirror the ID Token / session lifetime).

  A record carries at least one of the two logout URIs — a client with
  neither registers no logout session at all.

  `record/1` is idempotent on `(sid, client_id)`: re-issuing an ID Token for a
  session the RP already has refreshes the row rather than duplicating it.

  ## Delivery leases

  Logout delivery is at-least-once. `lease_targets/4` atomically reserves the
  matching rows for one worker without deleting them. The worker then calls
  `acknowledge_targets/2` for notifications it handed off successfully and
  `release_targets/2` for work that should become eligible for retry according
  to the store's documented policy. A worker crash needs no cleanup: another
  worker may reclaim the rows after `lease_expires_at`.

  Implementations MUST compare and update the lease in the same transaction
  that selects the targets. Acknowledge and release operations MUST match both
  the opaque `delivery_id` and `lease_id`; a stale worker must never delete or
  unlock a row reclaimed by a newer worker.

  This behaviour supplies persistence and leasing; it does not schedule
  deliveries. Hosts MUST run a bounded retry driver that leases newly available
  rows and revisits released rows and expired leases. The Ecto implementation
  bundled with `attesto_phoenix` wires that driver into its store sweeper and
  applies bounded exponential backoff to released rows.

  The lease callbacks are optional at the behaviour level during Attesto 2.x so
  stores written for the earlier `targets/1`, `delete/1`, and `take_targets/1`
  contract continue to compile. A consumer that performs durable delivery MUST
  capability-check and require all three lease callbacks before using the store.
  """

  @typedoc "A stored logout session record (see the module docs)."
  @type entry :: %{
          required(:sid) => String.t(),
          required(:subject) => String.t(),
          required(:client_id) => String.t(),
          optional(:backchannel_logout_uri) => String.t() | nil,
          optional(:session_required) => boolean(),
          optional(:frontchannel_logout_uri) => String.t() | nil,
          optional(:frontchannel_session_required) => boolean(),
          required(:expires_at) => non_neg_integer()
        }

  @typedoc """
  The criteria that select which sessions to log out. `:sid` scopes logout to
  one session (across each RP that holds it); `:subject` (used when no `sid`
  is known) scopes it to every session for the subject. At least one is set.
  """
  @type criteria :: %{optional(:sid) => String.t() | nil, optional(:subject) => String.t() | nil}

  @typedoc """
  A fan-out target: one RP to notify. `:backchannel_logout_uri` drives the
  `logout_token` POST; `:frontchannel_logout_uri` drives the logout page's
  iframe. Either may be `nil` (never both).
  """
  @type target :: %{
          optional(:delivery_id) => String.t(),
          required(:client_id) => String.t(),
          required(:backchannel_logout_uri) => String.t() | nil,
          required(:sid) => String.t() | nil,
          required(:session_required) => boolean(),
          required(:frontchannel_logout_uri) => String.t() | nil,
          required(:frontchannel_session_required) => boolean()
        }

  @typedoc "A cryptographically random identifier scoped to one delivery worker."
  @type lease_id :: String.t()

  @typedoc "The opaque persistent identifier carried by a leased target."
  @type delivery_id :: String.t()

  @doc """
  Record (idempotently on `(sid, client_id)`) that `client_id` holds a
  logout-capable session `sid` for `subject`, reachable at the entry's
  back-channel and/or front-channel logout URI. Called when an ID Token is
  minted to such a client.
  """
  @callback record(entry()) :: :ok

  @doc """
  Atomically lease every live target matched by `criteria` whose current lease
  is absent or expired.

  `now` and `lease_expires_at` are absolute unix seconds supplied by the
  caller; `lease_expires_at` MUST be greater than `now`. Returned targets carry
  the opaque `:delivery_id` needed by `acknowledge_targets/2` and
  `release_targets/2`.

  Two concurrent leases must never return the same row. Rows leased by a
  worker that crashes become eligible again once their lease expires.
  """
  @callback lease_targets(criteria(), lease_id(), non_neg_integer(), non_neg_integer()) :: [target()]

  @doc """
  Delete successfully handed-off targets from `lease_id`.

  Implementations MUST ignore identifiers that do not exist or are held by a
  different lease, making acknowledgement safe to repeat and safe after lease
  expiry/reclamation.
  """
  @callback acknowledge_targets(lease_id(), [delivery_id()]) :: :ok

  @doc """
  Release failed targets from `lease_id` so the store can make them eligible
  for retry according to its documented policy.

  Implementations MUST ignore identifiers that do not exist or are held by a
  different lease, making release safe to repeat and preventing stale workers
  from unlocking current work.
  """
  @callback release_targets(lease_id(), [delivery_id()]) :: :ok

  @doc """
  List the RP targets to notify for a logout. When `criteria` carries a `:sid`,
  scope to that session (every RP that received an ID Token under it); with no
  `:sid` but a `:subject`, scope to all of that subject's sessions. Returns the
  matching `t:target/0`s (possibly empty). Implementations SHOULD ignore
  already-expired rows.
  """
  @callback targets(criteria()) :: [target()]

  @doc """
  Remove the session rows matched by `criteria` (same `:sid`/`:subject`
  precedence as `targets/1`). Called after the fan-out so a session is
  enumerated for logout exactly once.
  """
  @callback delete(criteria()) :: :ok

  @doc """
  Atomically enumerate **and remove** the RP targets matched by `criteria`,
  returning them (same `:sid`/`:subject` precedence as `targets/1`). This is the
  end-session endpoint's fan-out primitive: doing the enumerate and the delete in
  one statement (e.g. `DELETE ... RETURNING`) means two concurrent logouts of the
  same session cannot both observe the rows and double-deliver, and no row that
  is inserted mid-logout is silently dropped. Already-expired rows are ignored.
  """
  @callback take_targets(criteria()) :: [target()]

  @optional_callbacks lease_targets: 4, acknowledge_targets: 2, release_targets: 2
end
