defmodule Attesto.Telemetry do
  @moduledoc """
  `:telemetry` events Attesto emits for security-relevant refusals.

  These events exist for one reason: some refusals are not routine. A
  refresh token presented twice, or a DPoP proof whose `jti` has already
  been seen, is the shape a stolen credential makes. A return value tells
  the calling function; it does not tell whoever is on call. Attaching a
  handler is how that signal reaches a pager, a SIEM, or an audit log
  without a host wrapping every call site.

  Ordinary failures are deliberately NOT events. An expired token, an
  unknown client, a wrong scope - these happen constantly in healthy
  traffic, and emitting them would bury the three below in noise.

  ## These are indicators, not verdicts

  None of them proves theft, and two are cheap for a client to produce
  deliberately:

    * A client can present its own sender-bound token under a second key as
      often as it likes. Verification fails before the proof's `jti` is
      claimed, so the same proof works repeatedly - one token and one proof
      can ring `sender_constraint_mismatch` indefinitely.
    * A mid-rotation key or certificate rotation, or a client with a stale
      cached key, produces the same mismatch for entirely benign reasons.

  So treat them as inputs to a decision rather than the decision:
  rate-limit and deduplicate by `client_id` before alerting, correlate
  across events and requests, and page on a pattern rather than on a single
  occurrence. `refresh_token.reuse_detected` is the one worth escalating
  fastest, because reaching it has already revoked the family - the damage
  it reports is done either way.

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

    * `:jti` - the replayed identifier, emitted unchanged because it is the
      only handle for correlating repeats. Chosen by the CLIENT, so see
      "What metadata contains" below before writing it anywhere.

  ### `[:attesto, :token, :sender_constraint_mismatch]`

  A token bound to a sender was presented with the WRONG proof of
  possession: a DPoP-bound token under a mismatched key (RFC 9449 §7.1),
  or an mTLS-bound token with a mismatched certificate (RFC 8705 §3).

  This is the weakest of the three. A token separated from its holder
  produces it - but so does a key rotation, a stale cached key, and a
  client that simply chooses to send the wrong one, repeatedly and for
  free. Correlate before concluding anything; see "indicators, not
  verdicts" above.

  A *missing* proof (`:dpop_proof_required`, `:mtls_cert_required`) does
  not emit. A client that has not implemented DPoP yet produces those
  constantly, and they say nothing about where the token is.

  Metadata:

    * `:binding` - `:dpop` or `:mtls`, the constraint that failed.
    * `:reason` - the specific refusal (`:dpop_binding_mismatch` or
      `:mtls_binding_mismatch`).
    * `:client_id` - the `client_id` claim of the presented token, when it
      carries one.

  ## What metadata contains, and what it does not

  Attesto never copies a credential, or a digest of one, into an event: no
  access token, refresh token, authorization code, client secret, assertion,
  or DPoP proof appears in metadata, and nothing emitted can be presented to
  obtain anything.

  It does emit selected FIELDS taken from credentials - `jti` is read out of
  the DPoP proof, `client_id` out of the presented token's claims - and
  those fields carry whatever their author put in them:

    * **`jti` is chosen by the client.** RFC 9449 constrains it only to be
      a unique string; this verifier additionally caps it at 256 bytes. A
      client may put anything there, including something that looks like -
      or is - one of its own credentials, and it is emitted unchanged so
      repeats can be correlated. A handler that writes metadata to a log
      is writing a remote party's chosen bytes to that log.
    * **`client_id`, `subject`, and `family_id` come from the host.** They
      are whatever the host's own identifiers are. `subject` in particular
      is usually personal data and falls under whatever retention policy
      covers your logs.

  So treat metadata as untrusted, attacker-influencable input on its way to
  wherever the handler sends it: escape it, bound it, and do not
  interpolate it into anything that parses. A client that puts its own live
  secret in `jti` will have that secret written wherever the handler writes.

  ## Handlers run synchronously

  `:telemetry` invokes handlers on the calling process, so a handler that
  blocks blocks the refusal that produced the event, and there is no timeout.
  Hand work to a queue, a task, or a `GenServer` and return; do not do I/O
  inline. A handler that raises or exits is caught and detached by
  `:telemetry` itself and cannot change the outcome - one that hangs can.

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

  # No catch here, deliberately.
  #
  # A handler that raises is already handled: `:telemetry.execute/3` catches it,
  # detaches the handler, and logs - so the refusal is never taken down by a bad
  # handler, and this function does not need to protect against one.
  #
  # What a blanket `catch _kind, _reason` DID protect against was the dispatcher
  # itself failing, and it did so by swallowing the failure whole.
  #
  # Removing it does not make every loss loud, and it is worth being exact:
  # with `:telemetry` stopped, `execute/3` finds an empty handler list and
  # returns `:ok`, so that particular loss is still silent. What the removal
  # buys is that a genuine dispatch failure surfaces instead of being absorbed.
  #
  # Delivery is SYNCHRONOUS and best-effort. A handler that blocks blocks the
  # refusal with it - `:telemetry` offers no timeout - so a handler must hand
  # work off and return promptly. That is a contract on the host, stated in the
  # moduledoc, not something this function can enforce.
  defp emit(event, metadata) do
    :telemetry.execute(event, %{system_time: System.system_time()}, metadata)
  end
end
