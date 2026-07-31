defmodule Attesto.Telemetry do
  @moduledoc """
  `:telemetry` events Attesto emits for security-relevant refusals.

  These events exist for one reason: some refusals are not routine. A
  refresh token presented twice, or a DPoP proof whose `jti` has already
  been seen, is evidence that someone holds a credential they should not.
  A return value tells the calling function; it does not tell whoever is
  on call. Attaching a handler to these events is how that signal reaches
  a pager, a SIEM, or an audit log without a host wrapping every call site.

  Ordinary failures are deliberately NOT events. An expired token, an
  unknown client, a wrong scope - these happen constantly in healthy
  traffic, and emitting them would bury the three below in noise.

  ## Events

  Every event carries `%{system_time: System.system_time()}` as its
  measurements and is emitted at the moment the refusal is decided.

  ### `[:attesto, :refresh_token, :reuse_detected]`

  A refresh token was presented after it had already been rotated, outside
  the idempotency window or without matching the original client, binding,
  and scope (RFC 6749 §10.4, RFC 9700 §4.14). **The whole family has been
  revoked** by the time this fires, so the legitimate client's session is
  already over; this event is the only notice anyone gets that it was not
  an ordinary logout.

  This is the highest-value event here. Treat it as an alert, not a log
  line.

  Metadata:

    * `:family_id` - the revoked family, for correlating the sessions this
      terminated.
    * `:client_id` - the client the family was issued to, when the token
      carried one.
    * `:subject` - the resource owner whose session was revoked.
    * `:generation` - the generation of the presented token.

  ### `[:attesto, :dpop, :replay_detected]`

  A DPoP proof carried a `jti` the replay store had already recorded
  (RFC 9449 §11.1) - the proof was captured and replayed, or a client is
  reusing identifiers it must not.

  Metadata:

    * `:jti` - the replayed identifier. Not a credential: it travels in
      the proof and is the only handle for correlating repeats.

  ### `[:attesto, :token, :sender_constraint_mismatch]`

  A token bound to a sender was presented with the wrong proof of
  possession, or with none: a DPoP-bound token under a mismatched key
  (RFC 9449 §7.1), or an mTLS-bound token with a mismatched certificate
  (RFC 8705 §3). The most likely explanation is a token that has left the
  holder it was issued to.

  Metadata:

    * `:binding` - `:dpop` or `:mtls`, the constraint that failed.
    * `:reason` - the specific refusal (`:dpop_binding_mismatch` or
      `:mtls_binding_mismatch`).
    * `:client_id` - the `client_id` claim of the presented token, when it
      carries one.

  ## What metadata never contains

  No access token, refresh token, authorization code, client secret, DPoP
  proof, or assertion - in plaintext or hashed. A handler writing metadata
  straight to a log must not thereby write a credential to disk. The
  identifiers above (`family_id`, `jti`, `client_id`, `subject`) are
  correlation handles, not secrets, and none of them can be presented to
  obtain anything.

  ## Attaching

      :telemetry.attach_many(
        "attesto-security",
        [
          [:attesto, :refresh_token, :reuse_detected],
          [:attesto, :dpop, :replay_detected],
          [:attesto, :token, :sender_constraint_mismatch]
        ],
        &MyApp.Security.handle_event/4,
        nil
      )

  ## Stability

  These names and metadata keys are public API and follow this package's
  version policy: keys may be added, but an existing event will not be
  renamed or have a documented key removed without a major version.
  """

  @refresh_token_reuse [:attesto, :refresh_token, :reuse_detected]
  @dpop_replay [:attesto, :dpop, :replay_detected]
  @sender_constraint_mismatch [:attesto, :token, :sender_constraint_mismatch]

  @doc "Every event this library emits, for `:telemetry.attach_many/4`."
  @spec events() :: [[atom()]]
  def events, do: [@refresh_token_reuse, @dpop_replay, @sender_constraint_mismatch]

  @doc false
  @spec refresh_token_reuse_detected(map()) :: :ok
  def refresh_token_reuse_detected(metadata) when is_map(metadata) do
    emit(@refresh_token_reuse, metadata)
  end

  @doc false
  @spec dpop_replay_detected(String.t()) :: :ok
  def dpop_replay_detected(jti) when is_binary(jti) do
    emit(@dpop_replay, %{jti: jti})
  end

  @doc false
  @spec sender_constraint_mismatch(:dpop | :mtls, atom(), map()) :: :ok
  def sender_constraint_mismatch(binding, reason, claims) when is_map(claims) do
    emit(@sender_constraint_mismatch, %{
      binding: binding,
      reason: reason,
      client_id: Map.get(claims, "client_id")
    })
  end

  # A handler that raises must not take the request down with it: these are
  # refusals, and the refusal itself is the security-relevant outcome.
  # `:telemetry.execute/3` already detaches a failing handler rather than
  # propagating, so this only guards the emit call itself.
  defp emit(event, metadata) do
    :telemetry.execute(event, %{system_time: System.system_time()}, metadata)
  catch
    _kind, _reason -> :ok
  end
end
