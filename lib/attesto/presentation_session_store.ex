defmodule Attesto.PresentationSessionStore do
  @moduledoc """
  Storage seam for verifier-side OID4VP presentation sessions.

  A session starts `pending` and may transition to `completed` exactly once.
  `complete/2` is security-critical: implementations MUST atomically guard the
  update on the current `pending` status and on the session being unexpired.
  Two concurrent wallet responses for one session therefore cannot both win or
  overwrite one another. A SQL implementation would use one conditional
  `UPDATE ... WHERE status = 'pending' AND expires_at > now`; the reference ETS
  implementation serializes this transition through its owner process.

  A completed session's verified result is read exactly once, through the
  required `take/1` callback, which atomically returns and clears it. `get/1`
  is non-consuming and serves only pending-session needs — the request object,
  the response-encryption key, and the `pending`/`completed` status. `get/1`
  MUST NOT return the completed result payload (`data.result`): the OID4VP
  `response_code` handed to the browser is the session id and transits the
  address bar, history, `Referer`, and logs, so a `get/1` that returned the
  claims would let anyone who captured it re-read the presented PII for the
  whole session TTL. Reading results only via the consuming `take/1` closes
  that. The reference store strips `:result` from `get/1`.
  """

  @type entry :: %{id: String.t(), data: map(), expires_at: integer()}

  @doc "Persist a new pending presentation session."
  @callback put(entry()) :: :ok

  @doc """
  Read a presentation session without consuming it.

  MUST NOT return the completed result payload (`data.result`) — that is read
  exactly once through `take/1`. Used to serve the request object and
  response-encryption key of a pending session and to observe `pending` vs
  `completed` status.
  """
  @callback get(id :: String.t()) :: {:ok, entry()} | :error

  @doc """
  Atomically transition an unexpired pending session to completed.

  The supplied result is retained with the session. Returns `:error` when the
  session is unknown, expired, or no longer pending.
  """
  @callback complete(id :: String.t(), result :: map()) :: :ok | :error

  @doc """
  Atomically fetch and clear an unexpired completed session.

  This is the ONLY way to read a completed session's verified result, and it is
  single-use: the row is deleted on read. Required — `Attesto.PresentationSession.result/2`
  calls it unconditionally.
  """
  @callback take(id :: String.t()) :: {:ok, entry()} | :error

  @doc """
  Atomically attach the signed request object to an unexpired pending session.

  Called once at creation time (before the session id is published), so it
  guards on `pending` like `complete/2`. Returns `:error` when the session is
  unknown, expired, or no longer pending.
  """
  @callback attach_request_object(id :: String.t(), request_object :: String.t()) :: :ok | :error

  @doc """
  Atomically attach the verifier's per-request (ephemeral) response-encryption
  private JWK to an unexpired pending session, for `direct_post.jwt` decryption.
  """
  @callback attach_response_encryption_jwk(id :: String.t(), jwk :: map()) :: :ok | :error

  @optional_callbacks attach_request_object: 2, attach_response_encryption_jwk: 2
end
