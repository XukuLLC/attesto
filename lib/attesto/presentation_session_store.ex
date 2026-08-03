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

  The optional `take/1` callback lets a host atomically poll and clear a
  completed result. `get/1` is non-consuming and is suitable for serving a
  request URI or polling without clearing the result.
  """

  @type entry :: %{id: String.t(), data: map(), expires_at: integer()}

  @doc "Persist a new pending presentation session."
  @callback put(entry()) :: :ok

  @doc "Read a presentation session without consuming it."
  @callback get(id :: String.t()) :: {:ok, entry()} | :error

  @doc """
  Atomically transition an unexpired pending session to completed.

  The supplied result is retained with the session. Returns `:error` when the
  session is unknown, expired, or no longer pending.
  """
  @callback complete(id :: String.t(), result :: map()) :: :ok | :error

  @doc "Atomically fetch and clear an unexpired completed session."
  @callback take(id :: String.t()) :: {:ok, entry()} | :error

  @optional_callbacks take: 1
end
