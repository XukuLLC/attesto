defmodule Attesto.LogoutSessionStore do
  @moduledoc """
  Storage seam for OpenID Connect Back-Channel Logout 1.0.

  Back-Channel Logout requires the OP to deliver a `logout_token` to every
  Relying Party that holds a session for the End-User when that session ends.
  To do that the OP must remember, for each `(session, RP)` pair, where to
  send the token. This behaviour is that memory: a row is recorded each time
  an ID Token is minted to a back-channel-logout-capable client (the OP is the
  party that mints those tokens, so it is the natural place to record the
  binding), and enumerated when the end-session endpoint fires.

  This is **not** the browser login session — attesto never models that; the
  host owns login and supplies the `sid`. This store only persists the OP-side
  `(sid, client_id) -> backchannel_logout_uri` delivery map, exactly as
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
    * `:backchannel_logout_uri` - where the `logout_token` is POSTed.
    * `:session_required` - the client's `backchannel_logout_session_required`
      (whether its `logout_token` MUST carry `sid`).
    * `:expires_at` - absolute expiry, unix seconds (so abandoned sessions are
      swept; mirror the ID Token / session lifetime).

  `record/1` is idempotent on `(sid, client_id)`: re-issuing an ID Token for a
  session the RP already has refreshes the row rather than duplicating it.
  """

  @typedoc "A stored back-channel-logout session record (see the module docs)."
  @type entry :: %{
          required(:sid) => String.t(),
          required(:subject) => String.t(),
          required(:client_id) => String.t(),
          required(:backchannel_logout_uri) => String.t(),
          required(:session_required) => boolean(),
          required(:expires_at) => non_neg_integer()
        }

  @typedoc """
  The criteria that select which sessions to log out. `:sid` scopes logout to
  one session (across each RP that holds it); `:subject` (used when no `sid`
  is known) scopes it to every session for the subject. At least one is set.
  """
  @type criteria :: %{optional(:sid) => String.t() | nil, optional(:subject) => String.t() | nil}

  @typedoc "A fan-out target: one RP to deliver a `logout_token` to."
  @type target :: %{
          required(:client_id) => String.t(),
          required(:backchannel_logout_uri) => String.t(),
          required(:sid) => String.t() | nil,
          required(:session_required) => boolean()
        }

  @doc """
  Record (idempotently on `(sid, client_id)`) that `client_id` holds a
  back-channel-logout-capable session `sid` for `subject`, reachable at
  `backchannel_logout_uri`. Called when an ID Token is minted to such a client.
  """
  @callback record(entry()) :: :ok

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
end
