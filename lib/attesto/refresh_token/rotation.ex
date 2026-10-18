defmodule Attesto.RefreshToken.Rotation do
  @moduledoc false

  alias Attesto.{NumericDate, Options, Secret, Store}
  alias Attesto.RefreshToken.Record, as: TokenRecord

  @default_ttl_seconds 14 * 24 * 60 * 60
  @default_rotation_grace_seconds 10

  def rotate(store, presented_token, opts \\ []) when is_atom(store) and is_binary(presented_token) and is_list(opts) do
    _allow_missing_client = allow_missing_client?(opts)
    grace = rotation_grace_seconds!(opts)
    ttl = Options.positive_integer!(opts, :ttl, @default_ttl_seconds)

    opts =
      opts
      |> Keyword.put(:rotation_grace_seconds, grace)
      |> Keyword.put(:ttl, ttl)
      |> Keyword.put(:now, NumericDate.non_negative_now!(opts))

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

  defp handle_refresh_lookup({:ok, record}, store, token_hash, opts) do
    if TokenRecord.loaded?(record, token_hash) do
      with :ok <- check_issuer(record.data, opts) do
        handle_valid_refresh_record(record, store, token_hash, opts)
      end
    else
      fail_initial_lookup(store, record, token_hash)
    end
  end

  defp handle_refresh_lookup(:error, _store, _token_hash, _opts), do: {:error, :invalid_grant}

  defp handle_refresh_lookup(invalid_return, store, token_hash, _opts) do
    fail_initial_lookup(store, invalid_return, token_hash)
  end

  defp handle_valid_refresh_record(%{consumed: true} = record, store, _token_hash, opts),
    do: maybe_idempotent_retry_or_reuse(store, record, opts)

  defp handle_valid_refresh_record(%{consumed: false} = record, store, token_hash, opts) do
    if TokenRecord.unconsumed?(record),
      do: rotate_unconsumed(store, record, opts),
      else: fail_initial_lookup(store, record, token_hash)
  end

  @spec fail_initial_lookup(module(), term(), binary()) :: no_return()
  defp fail_initial_lookup(store, record, token_hash) do
    metadata = %{
      operation: :lookup,
      reason: :store_contract_violation,
      revocation: :not_attempted
    }

    case TokenRecord.trusted_family_id(record, token_hash) do
      nil ->
        emit_rotation_state_preserving_original(metadata)

      family_id ->
        metadata = Map.put(metadata, :family_id, family_id)
        revocation = attempt_rotation_state_cleanup(store, family_id)
        emit_rotation_state_preserving_original(Map.put(metadata, :revocation, revocation))
    end

    Store.contract_violation!("refresh store", {:get, 1})
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
         :ok <- check_attestation(record.data, opts),
         {:ok, scope} <- resolve_scope(record.data, opts),
         {:ok, resource} <- resolve_resource(record.data, opts),
         {:ok, successor} <- same_successor(record, scope, resource) do
      case successor_status(store, record, successor, opts) do
        {:live, expires_at} ->
          {:ok,
           %{
             token: successor.token,
             family_id: record.family_id,
             generation: successor.generation,
             expires_at: expires_at,
             context: TokenRecord.public_context(successor.context)
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
    if TokenRecord.loaded?(child, token_hash) and
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
    if child.expires_at > NumericDate.now(opts),
      do: {:live, child.expires_at},
      else: {:state_error, :successor_expired}
  end

  defp classify_unconsumed_successor(_child, _consumed_at, _successor, _opts), do: {:state_error, :successor_invalid}

  # Validate on the read (no consumption), then atomically commit the parent,
  # child, and retry state. A recoverable validation failure leaves the parent
  # intact for a corrected retry.
  defp rotate_unconsumed(store, record, opts) do
    with :ok <- check_expiry(record, opts),
         :ok <- check_client(record.data, opts),
         :ok <- check_dpop(record.data, opts),
         :ok <- check_attestation(record.data, opts),
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
      TokenRecord.build_issue(
        successor_data,
        [
          family_id: parent.family_id,
          generation: parent.generation + 1,
          ttl: Keyword.fetch!(opts, :ttl),
          now: now
        ],
        @default_ttl_seconds
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
    if TokenRecord.valid_claim?(committed_parent, rotation.parent),
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
    child == expected and TokenRecord.loaded?(child, expected.token_hash) and
      TokenRecord.unconsumed?(child) and child.expires_at > now
  end

  defp valid_committed_parent?(committed, original, successor, now) do
    TokenRecord.loaded?(committed, original.token_hash) and committed.consumed == true and
      committed.consumed_at == now and committed.successor == successor and
      TokenRecord.same_identity?(committed, original)
  end

  defp rotated_successfully(issued, successor_data) do
    {:ok,
     %{
       token: issued.token,
       family_id: issued.family_id,
       generation: issued.generation,
       expires_at: issued.expires_at,
       context: TokenRecord.public_context(successor_data)
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
      _contract_violation -> Store.contract_violation!("refresh store", {:revoke_family, 1})
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

  defp check_issuer(data, opts) do
    case Keyword.fetch(opts, :issuer) do
      :error -> :ok
      {:ok, expected} -> if TokenRecord.issuer_matches?(data, expected), do: :ok, else: {:error, :issuer_mismatch}
    end
  end

  defp allow_missing_client?(opts) do
    Options.boolean!(opts, :allow_missing_client_id?, false)
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

      not TokenRecord.successor_context?(context, record.data) ->
        {:state_error, :successor_state_invalid}

      not equivalent_authorization_set?(context.scope, scope) or
          not equivalent_authorization_set?(context.resource, resource) ->
        {:error, :retry_request_mismatch}

      true ->
        {:ok, %{token: token, generation: generation, context: context}}
    end
  end

  defp equivalent_authorization_set?(left, right), do: MapSet.equal?(MapSet.new(left), MapSet.new(right))

  # ----- grant checks -----

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

  defp check_attestation(%{attestation_jkt: bound}, opts) do
    case Keyword.get(opts, :attestation_jkt) do
      nil -> {:error, :attestation_proof_required}
      ^bound -> :ok
      _ -> {:error, :attestation_binding_mismatch}
    end
  end

  defp check_attestation(_data, opts) do
    if is_nil(Keyword.get(opts, :attestation_jkt)),
      do: :ok,
      else: {:error, :attestation_proof_unexpected}
  end
end
