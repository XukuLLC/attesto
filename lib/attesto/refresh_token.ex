defmodule Attesto.RefreshToken do
  @moduledoc """
  Refresh-token issuance and rotation with reuse detection
  (RFC 6749 §6 / §10.4, OAuth 2.0 Security BCP).

  Each refresh token is single-use: presenting it (`rotate/3`) consumes it
  and mints a successor in the same *family*. A short idempotency window
  (10 seconds by default) lets the same client retry the just-consumed
  parent after a lost response and receive the same successor. The parent
  expiry remains authoritative: a cached successor is never returned after
  the consumed parent expires, even when the persisted retry deadline is
  later. Outside the intersection of those two fixed deadlines, or when the
  retry does not match the original client, binding, and scope, a rotated
  token is a captured-token signal and the entire family is revoked so neither
  the attacker nor the victim can continue, forcing a fresh authorization.

  This module is pure logic over a `Attesto.RefreshStore`; the store
  provides the atomic family-level `rotate/4` transaction on which reuse
  detection depends (see that behaviour's moduledoc). Token records use
  hashes, except that a
  positive rotation-grace window necessarily retains the plaintext
  successor until the window closes so the same credential can be returned
  after a lost response. That retry state is credential-equivalent and MUST
  be protected as described by
  `c:Attesto.RefreshStore.rotate/4`.

  ## DPoP binding

  A refresh token can be bound to a DPoP key (its issuing context carries
  a `:dpop_jkt`). Rotation then requires the caller to present the
  matching `:dpop_jkt` (the thumbprint of the key in the token-request's
  DPoP proof); an unbound token must be rotated without one - presenting a
  proof for an unbound token is `:dpop_proof_unexpected`. That fail-closed
  matrix mirrors `Attesto.Token`. It does NOT match
  `Attesto.AuthorizationCode`, which permits an unbound code to be redeemed
  alongside a token-request proof (the proof there binds the new access
  token, not the code); rotation is deliberately the stricter of the two.
  """

  alias Attesto.NumericDate
  alias Attesto.Scope
  alias Attesto.Secret
  alias Attesto.Thumbprint

  # 14 days. Refresh lifetime is a host policy; this is a sane default.
  @default_ttl_seconds 14 * 24 * 60 * 60
  @default_rotation_grace_seconds 10
  @stored_context_keys [:acr, :auth_time, :claims, :client_id, :dpop_jkt, :resource, :scope, :subject]

  @typedoc """
  Context for issuing an initial refresh token.

  `:dpop_jkt` is optional because the host must classify the client before
  issuing the token: RFC 9449 §5 requires DPoP-bound refresh tokens for public
  clients and prohibits DPoP binding for confidential clients. When this
  context is passed through
  `Attesto.AuthorizationCode.issue_refresh_and_finalize/6` for a
  DPoP-bound authorization grant, `nil` is the confidential-client choice and
  the grant's exact JKT is the public-client choice; a different JKT is
  rejected. Core does not determine the client class.
  """
  @type context :: %{
          required(:subject) => String.t(),
          optional(:scope) => [String.t()],
          optional(:resource) => [String.t()],
          optional(:acr) => String.t() | nil,
          optional(:auth_time) => non_neg_integer() | nil,
          optional(:client_id) => String.t(),
          optional(:dpop_jkt) => String.t() | nil,
          optional(:claims) => map()
        }

  @type issued :: %{
          token: String.t(),
          family_id: String.t(),
          generation: non_neg_integer()
        }

  @type rotated :: %{
          token: String.t(),
          family_id: String.t(),
          generation: non_neg_integer(),
          context: map()
        }

  @type issue_error ::
          :invalid_subject
          | :invalid_scope
          | :invalid_resource
          | :invalid_client_id
          | :invalid_dpop_jkt
          | :invalid_claims
          | :invalid_acr
          | :invalid_auth_time
          | :family_revoked

  @type rotate_error ::
          :invalid_grant
          | :reuse_detected
          | :grant_revoked
          | :temporarily_unavailable
          | :expired
          | :client_required
          | :client_mismatch
          | :invalid_scope
          | :invalid_target
          | :dpop_proof_required
          | :dpop_proof_unexpected
          | :dpop_binding_mismatch

  @doc """
  Issue a refresh token for `context` and persist it via `store`.

  `context` MUST carry `:subject`; optional `:scope` (list, default
  `[]`), `:client_id`, `:dpop_jkt` (binds the token to a DPoP key), and
  `:claims` (opaque host context).

  Options: `:ttl` (seconds, default 14 days) and `:now`. Public issuance
  always starts a fresh family at generation 0; only `rotate/3` can create a
  later generation, through the store's atomic rotation transaction.

  Returns `{:ok, %{token, family_id, generation}}` with the plaintext
  token to hand the client (only its hash is stored), or
  `{:error, reason}` on malformed `context`. A store may very rarely return
  `{:error, :family_revoked}` if a freshly generated family identifier
  collides with one of its retained revocation markers.
  """
  @spec issue(module(), context(), keyword()) :: {:ok, issued()} | {:error, issue_error()}
  def issue(store, context, opts \\ []) when is_atom(store) and is_map(context) and is_list(opts) do
    validate_issue_options!(opts)

    with {:ok, data} <- normalize_context(context) do
      case persist_issue(store, data, opts) do
        {:ok, issued} -> {:ok, issued}
        {:error, :family_revoked} = error -> error
        {:store_contract_violation} -> raise RuntimeError, "refresh store insert/1 violated its contract"
        {:store_failure, kind, value, stacktrace} -> :erlang.raise(kind, value, stacktrace)
      end
    end
  end

  @doc """
  Rotate a presented refresh token: consume it and mint its successor.

  On success returns `{:ok, %{token, family_id, generation, context}}`
  where `token` is the new refresh token, `generation` is the successor's
  generation, and `context` is the grant context to mint the next access
  token from.

  If the presented token was already rotated, an immediate matching retry
  returns the original successor within `:rotation_grace_seconds`;
  otherwise the whole family is revoked and `{:error, :reuse_detected}` is
  returned. Other failures include `:invalid_grant` (unknown token), `:expired`,
  `:grant_revoked`, `:temporarily_unavailable`, `:client_mismatch`,
  `:invalid_scope`, and the DPoP binding errors.

  Options:

    * `:now` - clock override.
    * `:dpop_jkt` - the presented proof's thumbprint (for DPoP-bound
      tokens).
    * `:client_id` - the authenticated presenting client. When the token
      was issued with a `client_id`, rotation is fail-closed: it MUST
      present a matching one (`:client_required` if absent,
      `:client_mismatch` if wrong), closing token substitution across
      clients (RFC 6749 §6 / §10.4). Pass `allow_missing_client_id?: true`
      to opt out. A token issued without a client binding skips the check.
    * `:scope` - a requested scope list. MUST be a subset of the token's
      granted scope; the successor then carries the narrowed scope. A
      request for any scope not granted is `:invalid_scope` (no
      escalation). Omitted, the successor carries the full granted scope.
    * `:ttl` - lifetime for the successor.
    * `:rotation_grace_seconds` - non-negative integer idempotency window for
      an immediate retry of the just-rotated token. Defaults to `10`; set `0`
      for strict reuse revocation. The window is fixed when the successor is
      issued: a later call may shorten it, but cannot extend it.

  Recoverable failures (`:client_mismatch`, `:invalid_scope`, `:expired`,
  the DPoP binding errors) are checked on a non-consuming read *before*
  the token is claimed, so they do NOT burn the token: a client that, say,
  retries with a corrected DPoP proof succeeds rather than tripping reuse
  detection. An already-consumed token is accepted only when its complete
  successor state proves it is the same request inside the fixed retry window.

  The parent claim, child insert, and retry-state persistence are one atomic
  `c:Attesto.RefreshStore.rotate/4` operation. Simultaneous matching requests
  therefore coalesce on the winner's complete committed successor instead of
  observing a partially rotated family.

  A store's documented `{:error, :invalid_rotation}` result means validation
  rejected the proposed transition before committing any mutation. It is
  reported as `{:error, :temporarily_unavailable}` with
  `revocation: :not_attempted`; adapters MUST use that result only when they
  can prove the transaction rolled back. Callback exceptions or ambiguous
  unexpected returns still trigger family cleanup because they may have
  committed.

  A `get/1` exception or contract violation emits the operational
  `[:attesto, :refresh_token, :rotation_state_failed]` event with
  `operation: :lookup`. The original callback exception or constant contract
  error is preserved. If a malformed returned record still binds the
  presented token hash to a non-empty family ID, that family is revoked before
  the contract error is raised; an untrusted or absent family is never used
  for cleanup.
  """
  @spec rotate(module(), String.t(), keyword()) :: {:ok, rotated()} | {:error, rotate_error()}
  def rotate(store, presented_token, opts \\ []) when is_atom(store) and is_binary(presented_token) and is_list(opts) do
    _allow_missing_client = allow_missing_client?(opts)
    grace = rotation_grace_seconds!(opts)
    ttl = ttl_seconds!(opts)

    opts =
      opts
      |> Keyword.put(:rotation_grace_seconds, grace)
      |> Keyword.put(:ttl, ttl)
      |> Keyword.put(:now, refresh_now!(opts))

    token_hash = Secret.hash(presented_token)

    case call_store_callback(fn -> store.get(token_hash) end) do
      {:returned, result} ->
        handle_refresh_lookup(result, store, token_hash, opts)

      {:failed, kind, value, stacktrace} ->
        emit_rotation_state_preserving_original(%{
          operation: :lookup,
          reason: store_failure_reason(kind),
          revocation: :not_attempted
        })

        :erlang.raise(kind, value, stacktrace)
    end
  end

  defp handle_refresh_lookup({:ok, %{consumed: true} = record}, store, token_hash, opts) do
    if valid_loaded_record?(record, token_hash),
      do: maybe_idempotent_retry_or_reuse(store, record, opts),
      else: fail_initial_lookup(store, record, token_hash)
  end

  defp handle_refresh_lookup({:ok, %{consumed: false} = record}, store, token_hash, opts) do
    if valid_loaded_record?(record, token_hash) and valid_unconsumed_record?(record),
      do: rotate_unconsumed(store, record, opts),
      else: fail_initial_lookup(store, record, token_hash)
  end

  defp handle_refresh_lookup(:error, _store, _token_hash, _opts), do: {:error, :invalid_grant}

  defp handle_refresh_lookup(invalid_return, store, token_hash, _opts) do
    fail_initial_lookup(store, invalid_return, token_hash)
  end

  defp fail_initial_lookup(store, record, token_hash) do
    metadata = %{
      operation: :lookup,
      reason: :store_contract_violation,
      revocation: :not_attempted
    }

    case trusted_family_id(record, token_hash) do
      nil ->
        emit_rotation_state_preserving_original(metadata)

      family_id ->
        metadata = Map.put(metadata, :family_id, family_id)
        revocation = attempt_rotation_state_cleanup(store, family_id)
        emit_rotation_state_preserving_original(Map.put(metadata, :revocation, revocation))
    end

    raise RuntimeError, "refresh store get/1 violated its contract"
  end

  defp maybe_idempotent_retry_or_reuse(store, record, opts) do
    case retry_window(record, opts) do
      :inside -> recover_successor_or_reuse(store, record, opts)
      :outside -> revoke_and_report_reuse(store, record)
      {:state_error, reason} -> fail_rotation_state(store, record, :recover_successor, reason)
    end
  end

  defp recover_successor_or_reuse(store, record, opts) do
    with :ok <- check_client(record.data, opts),
         :ok <- check_dpop(record.data, opts),
         {:ok, scope} <- resolve_scope(record.data, opts),
         {:ok, resource} <- resolve_resource(record.data, opts),
         {:ok, successor} <- same_successor(record, scope, resource) do
      case successor_status(store, record, successor, opts) do
        :live ->
          {:ok,
           %{
             token: successor.token,
             family_id: record.family_id,
             generation: successor.generation,
             context: successor.context
           }}

        :consumed ->
          revoke_and_report_reuse(store, record)

        {:state_error, reason} ->
          fail_rotation_state(store, record, :recover_successor, reason)

        {:store_failure, kind, value, stacktrace} ->
          fail_rotation_state_preserving(
            store,
            record,
            :recover_successor,
            store_failure_reason(kind),
            kind,
            value,
            stacktrace
          )
      end
    else
      {:state_error, reason} -> fail_rotation_state(store, record, :recover_successor, reason)
      _validation_or_retry_mismatch -> revoke_and_report_reuse(store, record)
    end
  end

  # Every path that has evidence of actual reuse goes through here, so
  # revoking the family and reporting it cannot drift apart. Missing or
  # malformed recovery state takes the separate operational-failure path.
  defp revoke_and_report_reuse(store, record) do
    metadata = %{
      family_id: record.family_id,
      client_id: record |> Map.get(:data, %{}) |> Map.get(:client_id),
      subject: record |> Map.get(:data, %{}) |> Map.get(:subject),
      generation: Map.get(record, :generation)
    }

    try do
      revoke_family!(store, record.family_id)
    rescue
      exception ->
        emit_reuse_preserving_original(Map.put(metadata, :revocation, :failed))
        reraise exception, __STACKTRACE__
    catch
      kind, value ->
        emit_reuse_preserving_original(Map.put(metadata, :revocation, :failed))
        :erlang.raise(kind, value, __STACKTRACE__)
    else
      :ok ->
        Attesto.Telemetry.refresh_token_reuse_detected(Map.put(metadata, :revocation, :succeeded))
        {:error, :reuse_detected}
    end
  end

  # OAuth 2.0 Security BCP §4.14.2 requires family invalidation when reuse is
  # detected. Our implementation-specific idempotent retry is safe ONLY while
  # the cached successor is itself still the live, unconsumed leaf -
  # i.e. the client genuinely lost the original rotation response and never used
  # the successor. If the successor has since been rotated, the chain has
  # demonstrably advanced past it and replaying the parent is true reuse. An
  # absent, malformed, or prematurely expired successor is instead a recovery
  # state failure: deny and revoke, but do not allege credential reuse.
  defp successor_status(store, parent, successor, opts) do
    family_id = parent.family_id
    generation = successor.generation
    context = successor.context
    token_hash = Secret.hash(successor.token)

    case call_store_callback(fn -> store.get(token_hash) end) do
      {:returned, {:ok, child}} ->
        classify_successor_status(child, token_hash, family_id, generation, context, opts)

      {:returned, :error} ->
        {:state_error, :successor_missing}

      {:returned, _invalid_return} ->
        {:state_error, :store_contract_violation}

      {:failed, kind, value, stacktrace} ->
        {:store_failure, kind, value, stacktrace}
    end
  end

  defp classify_successor_status(child, token_hash, family_id, generation, context, opts) do
    if valid_loaded_record?(child, token_hash) and
         child.family_id == family_id and child.generation == generation and child.data == context do
      classify_successor_liveness(child, opts)
    else
      {:state_error, :successor_invalid}
    end
  end

  defp classify_successor_liveness(%{consumed: true} = child, _opts) do
    classify_consumed_successor(Map.get(child, :consumed_at))
  end

  defp classify_successor_liveness(%{consumed: false} = child, opts) do
    classify_unconsumed_successor(
      child,
      Map.get(child, :consumed_at),
      Map.get(child, :successor),
      opts
    )
  end

  defp classify_consumed_successor(consumed_at) when is_integer(consumed_at), do: :consumed
  defp classify_consumed_successor(_consumed_at), do: {:state_error, :successor_invalid}

  defp classify_unconsumed_successor(child, nil, nil, opts) do
    if child.expires_at > NumericDate.now(opts), do: :live, else: {:state_error, :successor_expired}
  end

  defp classify_unconsumed_successor(_child, _consumed_at, _successor, _opts), do: {:state_error, :successor_invalid}

  # Validate on the read (no consumption), then atomically commit the parent,
  # child, and retry state. A recoverable validation failure leaves the parent
  # intact for a corrected retry.
  defp rotate_unconsumed(store, record, opts) do
    with :ok <- check_client(record.data, opts),
         :ok <- check_expiry(record, opts),
         :ok <- check_dpop(record.data, opts),
         {:ok, scope} <- resolve_scope(record.data, opts),
         {:ok, resource} <- resolve_resource(record.data, opts) do
      rotate_successor(store, record, scope, resource, opts)
    end
  end

  defp rotate_successor(store, parent, scope, resource, opts),
    do: rotate_successor(store, parent, scope, resource, opts, 3)

  defp rotate_successor(store, parent, scope, resource, opts, attempts_left) do
    now = NumericDate.now(opts)
    successor_data = %{parent.data | scope: scope, resource: resource}

    {issued, child} =
      build_issue(successor_data,
        family_id: parent.family_id,
        generation: parent.generation + 1,
        ttl: Keyword.fetch!(opts, :ttl),
        now: now
      )

    successor = successor_state(issued, successor_data, child, opts)

    rotation = %{
      store: store,
      parent: parent,
      scope: scope,
      resource: resource,
      opts: opts,
      attempts_left: attempts_left,
      issued: issued,
      child: child,
      successor: successor,
      successor_data: successor_data,
      now: now
    }

    fn -> store.rotate(parent.token_hash, child, successor, now: now) end
    |> call_store_callback()
    |> handle_rotate_result(rotation)
  end

  defp handle_rotate_result({:returned, {:ok, committed_parent, committed_child}}, rotation) do
    finish_atomic_rotation(committed_parent, committed_child, rotation)
  end

  defp handle_rotate_result({:returned, {:reuse, committed_parent}}, rotation) do
    if valid_claim_record?(committed_parent, rotation.parent, :reuse),
      do: maybe_idempotent_retry_or_reuse(rotation.store, committed_parent, rotation.opts),
      else:
        fail_rotation_state(
          rotation.store,
          rotation.parent,
          :rotate_successor,
          :store_contract_violation
        )
  end

  defp handle_rotate_result({:returned, {:error, :family_revoked}}, _rotation), do: {:error, :grant_revoked}

  defp handle_rotate_result({:returned, {:error, :expired}}, _rotation), do: {:error, :expired}

  defp handle_rotate_result({:returned, {:error, :retry_state_unavailable}}, rotation),
    do: report_rotation_unavailable(rotation.parent, :retry_state_unavailable)

  defp handle_rotate_result({:returned, {:error, :token_conflict}}, %{attempts_left: attempts_left} = rotation)
       when attempts_left > 0 do
    rotate_successor(
      rotation.store,
      rotation.parent,
      rotation.scope,
      rotation.resource,
      rotation.opts,
      attempts_left - 1
    )
  end

  defp handle_rotate_result({:returned, {:error, :token_conflict}}, rotation),
    do: report_rotation_unavailable(rotation.parent, :token_conflict)

  defp handle_rotate_result({:returned, {:error, :family_integrity_error}}, rotation),
    do: report_revoked_integrity_failure(rotation.parent, :generation_conflict)

  defp handle_rotate_result({:returned, {:error, :invalid_rotation}}, rotation),
    do: report_rotation_unavailable(rotation.parent, :invalid_rotation)

  defp handle_rotate_result({:returned, :error}, _rotation), do: {:error, :invalid_grant}

  defp handle_rotate_result({:returned, _invalid_return}, rotation),
    do: fail_rotation_state(rotation.store, rotation.parent, :rotate_successor, :store_contract_violation)

  defp handle_rotate_result({:failed, kind, value, stacktrace}, rotation) do
    fail_rotation_state_preserving(
      rotation.store,
      rotation.parent,
      :rotate_successor,
      store_failure_reason(kind),
      kind,
      value,
      stacktrace
    )
  end

  defp finish_atomic_rotation(committed_parent, committed_child, rotation) do
    if valid_committed_parent?(
         committed_parent,
         rotation.parent,
         rotation.successor,
         rotation.now
       ) and valid_committed_child?(committed_child, rotation.child, rotation.now),
       do: rotated_successfully(rotation.issued, rotation.successor_data),
       else:
         fail_rotation_state(
           rotation.store,
           rotation.parent,
           :rotate_successor,
           :store_contract_violation
         )
  end

  defp successor_state(issued, successor_data, child, opts) do
    now = NumericDate.now(opts)
    grace = Keyword.fetch!(opts, :rotation_grace_seconds)

    if grace == 0 do
      %{retry_until: now, recoverable: false}
    else
      %{
        token: issued.token,
        generation: issued.generation,
        context: successor_data,
        retry_until: min(now + grace, child.expires_at - 1)
      }
    end
  end

  defp valid_committed_child?(child, expected, now) do
    child == expected and valid_loaded_record?(child, expected.token_hash) and
      valid_unconsumed_record?(child) and child.expires_at > now
  end

  defp valid_committed_parent?(committed, original, successor, now) do
    valid_loaded_record?(committed, original.token_hash) and committed.consumed == true and
      committed.consumed_at == now and committed.successor == successor and
      same_claim_identity?(committed, original)
  end

  defp persist_issue(store, data, opts), do: persist_issue(store, data, opts, 3)

  defp persist_issue(store, data, opts, attempts_left) do
    {issued, record} = build_issue(data, opts)

    case call_store_callback(fn -> store.insert(record) end) do
      {:returned, :ok} ->
        {:ok, issued}

      {:returned, {:error, :family_revoked}} ->
        {:error, :family_revoked}

      {:returned, {:error, :conflict}} when attempts_left > 0 ->
        persist_issue(store, data, opts, attempts_left - 1)

      {:returned, {:error, :conflict}} ->
        {:store_contract_violation}

      {:returned, _invalid_return} ->
        {:store_contract_violation}

      {:failed, kind, value, stacktrace} ->
        {:store_failure, kind, value, stacktrace}
    end
  end

  defp build_issue(data, opts) do
    token = Secret.generate()
    family_id = Keyword.get_lazy(opts, :family_id, fn -> Secret.generate(16) end)
    generation = Keyword.get(opts, :generation, 0)
    ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)

    record = %{
      token_hash: Secret.hash(token),
      family_id: family_id,
      generation: generation,
      data: data,
      expires_at: NumericDate.now(opts) + ttl,
      consumed: false,
      consumed_at: nil,
      successor: nil
    }

    {%{token: token, family_id: family_id, generation: generation}, record}
  end

  defp rotated_successfully(issued, successor_data) do
    {:ok,
     %{
       token: issued.token,
       family_id: issued.family_id,
       generation: issued.generation,
       context: successor_data
     }}
  end

  defp fail_rotation_state(store, record, operation, reason) do
    metadata = rotation_state_metadata(record, operation, reason)

    try do
      revoke_family!(store, record.family_id)
    rescue
      exception ->
        Attesto.Telemetry.refresh_token_rotation_state_failed(Map.put(metadata, :revocation, :failed))
        reraise exception, __STACKTRACE__
    catch
      kind, value ->
        Attesto.Telemetry.refresh_token_rotation_state_failed(Map.put(metadata, :revocation, :failed))
        :erlang.raise(kind, value, __STACKTRACE__)
    else
      :ok ->
        Attesto.Telemetry.refresh_token_rotation_state_failed(Map.put(metadata, :revocation, :succeeded))
        {:error, :grant_revoked}
    end
  end

  defp report_rotation_unavailable(record, reason) do
    record
    |> rotation_state_metadata(:rotate_successor, reason)
    |> Map.put(:revocation, :not_attempted)
    |> Attesto.Telemetry.refresh_token_rotation_state_failed()

    {:error, :temporarily_unavailable}
  end

  defp report_revoked_integrity_failure(record, reason) do
    record
    |> rotation_state_metadata(:rotate_successor, reason)
    |> Map.put(:revocation, :succeeded)
    |> Attesto.Telemetry.refresh_token_rotation_state_failed()

    {:error, :grant_revoked}
  end

  defp fail_rotation_state_preserving(store, record, operation, reason, kind, value, stacktrace) do
    metadata = rotation_state_metadata(record, operation, reason)
    revocation = attempt_rotation_state_cleanup(store, record.family_id)
    emit_rotation_state_preserving_original(Map.put(metadata, :revocation, revocation))
    :erlang.raise(kind, value, stacktrace)
  end

  defp rotation_state_metadata(record, operation, reason) do
    %{
      operation: operation,
      reason: reason,
      family_id: record.family_id,
      client_id: record |> Map.get(:data, %{}) |> Map.get(:client_id),
      subject: record |> Map.get(:data, %{}) |> Map.get(:subject),
      generation: Map.get(record, :generation)
    }
  end

  defp attempt_rotation_state_cleanup(store, family_id) do
    case store.revoke_family(family_id) do
      :ok -> :succeeded
      _contract_violation -> :failed
    end
  catch
    _kind, _value -> :failed
  end

  defp revoke_family!(store, family_id) do
    case store.revoke_family(family_id) do
      :ok -> :ok
      _contract_violation -> raise RuntimeError, "refresh store revoke_family/1 violated its contract"
    end
  end

  # The callback failure is already being re-raised. A telemetry dispatcher
  # failure must not replace it with a less useful secondary exception.
  defp emit_rotation_state_preserving_original(metadata) do
    Attesto.Telemetry.refresh_token_rotation_state_failed(metadata)
  catch
    _kind, _value -> :ok
  end

  defp emit_reuse_preserving_original(metadata) do
    Attesto.Telemetry.refresh_token_reuse_detected(metadata)
  catch
    _kind, _value -> :ok
  end

  defp store_failure_reason(:error), do: :store_raised
  defp store_failure_reason(:throw), do: :store_threw
  defp store_failure_reason(:exit), do: :store_exited

  # RFC 6749 §10.4: a refresh token must only be redeemed by the client it
  # was issued to. Fail closed by default - when the token carries a
  # `client_id`, rotation MUST present a matching one (`:client_required`
  # when absent, `:client_mismatch` when wrong) unless the caller opts out
  # with `allow_missing_client_id?: true`. A token with no client binding
  # skips the check entirely.
  defp check_client(%{client_id: stored}, opts) when is_binary(stored) do
    case Keyword.get(opts, :client_id) do
      nil -> if allow_missing_client?(opts), do: :ok, else: {:error, :client_required}
      ^stored -> :ok
      _ -> {:error, :client_mismatch}
    end
  end

  defp check_client(_data, _opts), do: :ok

  defp allow_missing_client?(opts) do
    case Keyword.fetch(opts, :allow_missing_client_id?) do
      :error -> false
      {:ok, value} when is_boolean(value) -> value
      {:ok, _value} -> raise ArgumentError, ":allow_missing_client_id? must be true or false"
    end
  end

  # RFC 6749 §6: the requested scope MUST be a subset of the originally
  # granted scope. Narrowing is allowed; widening is refused. No request
  # means the successor keeps the full granted scope.
  defp resolve_scope(%{scope: granted}, opts) do
    case Keyword.get(opts, :scope) do
      nil ->
        {:ok, granted}

      requested when is_list(requested) ->
        if Enum.all?(requested, &(&1 in granted)),
          do: {:ok, Enum.uniq(requested)},
          else: {:error, :invalid_scope}

      _ ->
        {:error, :invalid_scope}
    end
  end

  # RFC 8707 + RFC 6749 §6 (mirrors scope narrowing): a refresh request may
  # narrow the bound resource set via a `:resource` opt but never widen it - a
  # requested resource not among the originally granted set is `:invalid_target`.
  # No `:resource` opt keeps the full granted set, so a refreshed access token
  # stays audienced to the resources the original grant authorized.
  defp resolve_resource(data, opts) do
    granted = Map.get(data, :resource, [])

    case Keyword.get(opts, :resource) do
      nil ->
        {:ok, granted}

      requested when is_list(requested) ->
        if Enum.all?(requested, &(&1 in granted)),
          do: {:ok, Enum.uniq(requested)},
          else: {:error, :invalid_target}

      _ ->
        {:error, :invalid_target}
    end
  end

  defp call_store_callback(callback) do
    {:returned, callback.()}
  catch
    kind, value -> {:failed, kind, value, __STACKTRACE__}
  end

  defp valid_loaded_record?(record, token_hash) do
    is_map(record) and Map.get(record, :token_hash) == token_hash and
      non_empty_binary?(Map.get(record, :family_id)) and
      is_integer(Map.get(record, :generation)) and Map.get(record, :generation) >= 0 and
      valid_stored_context?(Map.get(record, :data)) and is_integer(Map.get(record, :expires_at)) and
      is_boolean(Map.get(record, :consumed))
  end

  # A malformed record must not be allowed to name an arbitrary family for
  # cleanup. The hash binding is the minimum trustworthy link back to the
  # credential that was presented; no other malformed fields are copied into
  # telemetry.
  defp trusted_family_id(record, token_hash) when is_map(record) do
    if Map.get(record, :token_hash) == token_hash and non_empty_binary?(Map.get(record, :family_id)) do
      Map.get(record, :family_id)
    end
  end

  defp trusted_family_id(_record, _token_hash), do: nil

  defp valid_unconsumed_record?(record) do
    is_nil(Map.get(record, :consumed_at)) and is_nil(Map.get(record, :successor))
  end

  defp valid_claim_record?(claimed, original, :reuse) do
    valid_loaded_record?(claimed, original.token_hash) and Map.get(claimed, :consumed) == true and
      is_integer(Map.get(claimed, :consumed_at)) and same_claim_identity?(claimed, original)
  end

  defp same_claim_identity?(claimed, original) do
    Enum.all?([:token_hash, :family_id, :generation, :data, :expires_at], fn key ->
      Map.fetch(claimed, key) == Map.fetch(original, key)
    end)
  end

  defp valid_stored_context?(
         %{
           subject: subject,
           scope: scope,
           resource: resource,
           client_id: client_id,
           dpop_jkt: dpop_jkt,
           acr: acr,
           auth_time: auth_time,
           claims: claims
         } = context
       ) do
    # The adapter contract calls this the canonical context: all and only these
    # keys must survive a round trip. Host-specific values belong inside
    # `:claims`, so an extra sibling key is a malformed record, not ignored data.
    exact_context_keys?(context) and
      non_empty_binary?(subject) and valid_scope?(scope) and valid_resource?(resource) and
      valid_optional_client_id?(client_id) and valid_optional_jkt?(dpop_jkt) and is_map(claims) and
      valid_optional_acr?(acr) and valid_optional_auth_time?(auth_time)
  end

  defp valid_stored_context?(_malformed), do: false

  defp exact_context_keys?(context),
    do:
      map_size(context) == length(@stored_context_keys) and Enum.all?(@stored_context_keys, &Map.has_key?(context, &1))

  defp retry_window(record, opts) do
    grace = Keyword.fetch!(opts, :rotation_grace_seconds)
    consumed_at = Map.get(record, :consumed_at)
    now = NumericDate.now(opts)

    cond do
      not is_integer(consumed_at) ->
        {:state_error, :consumed_at_missing}

      consumed_at < 0 ->
        {:state_error, :consumed_at_invalid}

      true ->
        retry_window_after_consumption_validation(record, consumed_at, now, grace)
    end
  end

  defp retry_window_after_consumption_validation(record, consumed_at, now, grace) do
    cond do
      # A valid store can only consume a live parent, so its committed
      # consumption instant must precede the parent's expiry. Treat a broken
      # persisted relation as an operational state fault rather than evidence
      # of token reuse.
      Map.get(record, :expires_at) <= consumed_at ->
        {:state_error, :consumed_at_after_expiry}

      # The parent expiry is independent of the successor's persisted retry
      # deadline. A sweeper may retain an expired consumed parent so a replay
      # can still revoke its family, but that retention must never make the
      # cached successor usable after the parent's strict expiry boundary.
      Map.get(record, :expires_at) <= max(now, consumed_at) ->
        :outside

      now < consumed_at and consumed_at - now > grace ->
        {:state_error, :clock_before_consumption}

      grace == 0 ->
        :outside

      max(now, consumed_at) - consumed_at > grace ->
        :outside

      true ->
        # A serving node may lag the node that committed `consumed_at`. Clamp
        # only bounded backward skew to the committed instant, so a retry can
        # use the already-fixed deadline without extending the grace window.
        retry_deadline_status(Map.get(record, :successor), consumed_at, max(now, consumed_at))
    end
  end

  defp retry_deadline_status(%{retry_until: retry_until, recoverable: false}, consumed_at, now)
       when is_integer(retry_until) do
    cond do
      retry_until < consumed_at -> {:state_error, :retry_deadline_invalid}
      retry_until == consumed_at -> :outside
      now > retry_until -> :outside
      true -> {:state_error, :successor_state_unavailable}
    end
  end

  defp retry_deadline_status(%{retry_until: retry_until}, consumed_at, now) when is_integer(retry_until) do
    cond do
      retry_until < consumed_at -> {:state_error, :retry_deadline_invalid}
      now <= retry_until -> :inside
      true -> :outside
    end
  end

  defp retry_deadline_status(%{retry_until: _invalid}, _consumed_at, _now), do: {:state_error, :retry_deadline_invalid}

  defp retry_deadline_status(_missing_or_invalid_successor, _consumed_at, _now),
    do: {:state_error, :successor_state_missing}

  defp rotation_grace_seconds!(opts) do
    case Keyword.get(opts, :rotation_grace_seconds, @default_rotation_grace_seconds) do
      grace when is_integer(grace) and grace >= 0 ->
        grace

      other ->
        raise ArgumentError,
              ":rotation_grace_seconds must be a non-negative integer; got #{inspect(other)}"
    end
  end

  defp validate_issue_options!(opts) do
    _ttl = ttl_seconds!(opts)
    _now = refresh_now!(opts)

    if Keyword.has_key?(opts, :family_id) or Keyword.has_key?(opts, :generation) do
      raise ArgumentError,
            ":family_id and :generation are internal rotation state; public issuance always starts a new family"
    end

    :ok
  end

  defp ttl_seconds!(opts) do
    case Keyword.get(opts, :ttl, @default_ttl_seconds) do
      ttl when is_integer(ttl) and ttl > 0 -> ttl
      _invalid -> raise ArgumentError, ":ttl must be a positive integer"
    end
  end

  defp refresh_now!(opts) do
    case NumericDate.now(opts) do
      now when is_integer(now) and now >= 0 -> now
      _negative -> raise ArgumentError, ":now must be a non-negative NumericDate"
    end
  end

  defp same_successor(record, scope, resource) do
    case Map.get(record, :successor) do
      %{token: token, generation: generation, context: context}
      when is_binary(token) and token != "" and is_integer(generation) and is_map(context) ->
        classify_successor(record, token, generation, context, scope, resource)

      nil ->
        {:state_error, :successor_state_missing}

      _ ->
        {:state_error, :successor_state_invalid}
    end
  end

  defp classify_successor(record, token, generation, context, scope, resource) do
    cond do
      generation != record.generation + 1 ->
        {:state_error, :successor_state_invalid}

      not valid_successor_context?(context, record.data) ->
        {:state_error, :successor_state_invalid}

      not equivalent_authorization_set?(context.scope, scope) or
          not equivalent_authorization_set?(context.resource, resource) ->
        {:error, :retry_request_mismatch}

      true ->
        {:ok, %{token: token, generation: generation, context: context}}
    end
  end

  defp valid_successor_context?(context, parent) do
    valid_stored_context?(context) and
      Enum.all?([:subject, :client_id, :dpop_jkt, :acr, :auth_time, :claims], fn key ->
        Map.get(context, key) == Map.get(parent, key)
      end) and authorization_subset?(context.scope, parent.scope) and
      authorization_subset?(context.resource, parent.resource)
  end

  defp authorization_subset?(requested, granted) do
    MapSet.subset?(MapSet.new(requested), MapSet.new(granted))
  end

  defp equivalent_authorization_set?(left, right), do: MapSet.equal?(MapSet.new(left), MapSet.new(right))

  # ----- validation -----

  defp normalize_context(context) do
    scope = Map.get(context, :scope, [])
    resource = Map.get(context, :resource, [])
    dpop_jkt = Map.get(context, :dpop_jkt)

    with :ok <- validate_primary_context(context, scope, resource),
         :ok <- validate_supplemental_context(context, dpop_jkt) do
      {:ok, build_data(context, scope, resource, dpop_jkt)}
    end
  end

  defp validate_primary_context(context, scope, resource) do
    cond do
      not non_empty_binary?(Map.get(context, :subject)) -> {:error, :invalid_subject}
      not valid_scope?(scope) -> {:error, :invalid_scope}
      not valid_resource?(resource) -> {:error, :invalid_resource}
      not valid_optional_client_id?(Map.get(context, :client_id)) -> {:error, :invalid_client_id}
      true -> :ok
    end
  end

  defp validate_supplemental_context(context, dpop_jkt) do
    cond do
      not valid_optional_jkt?(dpop_jkt) -> {:error, :invalid_dpop_jkt}
      not is_map(Map.get(context, :claims, %{})) -> {:error, :invalid_claims}
      not valid_optional_acr?(Map.get(context, :acr)) -> {:error, :invalid_acr}
      not valid_optional_auth_time?(Map.get(context, :auth_time)) -> {:error, :invalid_auth_time}
      true -> :ok
    end
  end

  defp build_data(context, scope, resource, dpop_jkt) do
    %{
      subject: context.subject,
      scope: scope,
      resource: resource,
      client_id: Map.get(context, :client_id),
      dpop_jkt: dpop_jkt,
      # RFC 9470 / OIDC Core §2: the authentication context (`acr`/`auth_time`)
      # of the ORIGINAL end-user authentication. Carried through rotation
      # unchanged (successor_data only narrows scope/resource), so a
      # refresh-minted access token reports the original auth event - a refresh
      # never makes the authentication "fresher".
      acr: Map.get(context, :acr),
      auth_time: Map.get(context, :auth_time),
      claims: Map.get(context, :claims, %{})
    }
  end

  defp valid_optional_acr?(nil), do: true
  defp valid_optional_acr?(acr), do: non_empty_binary?(acr)
  defp valid_optional_client_id?(nil), do: true
  defp valid_optional_client_id?(client_id), do: non_empty_binary?(client_id)
  defp valid_optional_auth_time?(nil), do: true
  defp valid_optional_auth_time?(auth_time), do: is_integer(auth_time) and auth_time >= 0

  defp check_expiry(%{expires_at: expires_at}, opts) do
    if expires_at > NumericDate.now(opts), do: :ok, else: {:error, :expired}
  end

  defp check_dpop(%{dpop_jkt: bound}, opts) when is_binary(bound) do
    case Keyword.get(opts, :dpop_jkt) do
      # Only a wholly absent proof is "required"; any present-but-wrong
      # value (mismatched binary or malformed) is a binding mismatch.
      nil -> {:error, :dpop_proof_required}
      ^bound -> :ok
      _ -> {:error, :dpop_binding_mismatch}
    end
  end

  defp check_dpop(_data, opts) do
    case Keyword.get(opts, :dpop_jkt) do
      nil -> :ok
      _ -> {:error, :dpop_proof_unexpected}
    end
  end

  # ----- helpers -----

  defp non_empty_binary?(v), do: is_binary(v) and v != ""
  defp valid_scope?(scope), do: Scope.valid_list?(scope)
  defp valid_resource?(resource), do: is_list(resource) and Enum.all?(resource, &non_empty_binary?/1)
  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(jkt), do: Thumbprint.valid?(jkt)
end
