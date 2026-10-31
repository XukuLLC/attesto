defmodule Attesto.PollingGrant do
  @moduledoc false

  # Redemption state machine shared by the two polling grants: CIBA poll mode
  # (CIBA Core §11) and the device authorization grant (RFC 8628 §3.5).
  #
  # Each flow keeps its own record validation, its own pre-poll checks (expiry,
  # binding, push mode) and its own error vocabulary for decisions. What lives
  # here once is the part both flows must get identically right: which status
  # leads to which token-endpoint outcome, that only a genuinely pending record
  # reaches the store's throttling `poll/2`, that an approved record is redeemed
  # through the store's atomic `consume/2`, and how every store return value is
  # checked before it is trusted.

  @typedoc """
  A flow's redemption parameters.

    * `:store` / `:key` - the store module and the key its `poll/2` and
      `consume/2` take (the hashed `auth_req_id` or device code).
    * `:now` - the request time, passed to `consume/2`.
    * `:poll_args` - the second argument to `poll/2`.
    * `:poll_transition?` / `:consume_transition?` - `(trusted, returned)`
      predicates that reject a store result whose identity, bindings, or
      status do not follow from the trusted record.
    * `:after_poll` - checks re-run on the polled record before its status is
      acted on (`fn _ -> :ok end` when the transition predicate suffices).
    * `:to_grant` - builds the grant from the consumed record.
    * `:contract_error` - raises the flow's store-contract violation for the
      named callback.
  """
  @type spec :: %{
          required(:store) => module(),
          required(:key) => binary(),
          required(:now) => non_neg_integer(),
          required(:poll_args) => map(),
          required(:poll_transition?) => (map(), map() -> boolean()),
          required(:consume_transition?) => (map(), map() -> boolean()),
          required(:after_poll) => (map() -> :ok | {:error, atom()}),
          required(:to_grant) => (map() -> term()),
          required(:contract_error) => (atom() -> no_return())
        }

  @decision_errors [:not_found, :already_decided, :expired]

  @doc false
  # Apply the token-endpoint outcome for a record that already passed the
  # flow's expiry and binding checks. Only a pending record reaches `poll/2`,
  # so the interval throttle (which writes `last_polled_at` and can answer
  # `slow_down`) never fires for a decided, consumed, or unauthorized request,
  # and only an approved record reaches `consume/2`.
  @spec resolve(map(), spec()) :: {:ok, term()} | {:error, atom()}
  def resolve(%{status: :pending} = trusted, spec), do: poll(trusted, spec)
  def resolve(%{status: :approved} = trusted, spec), do: consume(trusted, spec)
  def resolve(%{status: :denied}, _spec), do: {:error, :access_denied}
  def resolve(%{status: :consumed}, _spec), do: {:error, :invalid_grant}

  @doc false
  # The grant fields both flows derive the same way from a consumed record. The
  # granted scope wins over the requested one when the decision narrowed it.
  @spec grant_fields(map()) :: keyword()
  def grant_fields(record) when is_map(record) do
    data = Map.get(record, :data, %{})

    [
      claims: Map.get(record, :granted_claims) || %{},
      client_id: Map.get(data, :client_id),
      dpop_jkt: Map.get(data, :dpop_jkt),
      resource: Map.get(data, :resource, []),
      scope: Map.get(record, :granted_scope) || Map.get(data, :scope, []),
      subject: Map.get(record, :subject)
    ]
  end

  @doc false
  # The polling client must be the one the request was issued to (CIBA Core
  # §11 "issued to another Client", RFC 8628 §3.4).
  @spec check_client(map(), map()) :: :ok | {:error, :invalid_grant}
  def check_client(%{data: %{client_id: bound}}, %{client_id: presented}) do
    if is_binary(bound) and bound == presented, do: :ok, else: {:error, :invalid_grant}
  end

  def check_client(_record, _params), do: {:error, :invalid_grant}

  @doc false
  # RFC 9449 §10 holder-of-key: a request pre-bound to a DPoP key is redeemable
  # only with a matching proof. An unbound request accepts any (or no) presented
  # key, which the caller may use to mint a DPoP-bound token.
  @spec check_dpop(map(), map()) :: :ok | {:error, :invalid_grant}
  def check_dpop(%{data: %{dpop_jkt: bound}}, params) when is_binary(bound) and bound != "" do
    if Map.get(params, :dpop_jkt) == bound, do: :ok, else: {:error, :invalid_grant}
  end

  def check_dpop(_record, _params), do: :ok

  @doc false
  # Check the result of a store's `approve/3` or `deny/2` (`callback`): a
  # returned record must satisfy the flow's transition predicate before `on_ok`
  # sees it, a decision error passes through, and anything else is a
  # store-contract violation.
  @spec decision_result(term(), (map() -> boolean()), (map() -> result), (atom() -> no_return()), :approve | :deny) ::
          result | {:error, :not_found | :already_decided | :expired}
        when result: term()
  def decision_result({:ok, record}, transition?, on_ok, contract_error, callback)
      when is_map(record) and is_map_key(record, :status) do
    if transition?.(record), do: on_ok.(record), else: contract_error.(callback)
  end

  def decision_result({:error, reason} = error, _transition?, _on_ok, _contract_error, _callback)
      when reason in @decision_errors, do: error

  def decision_result(_unexpected, _transition?, _on_ok, contract_error, callback), do: contract_error.(callback)

  # `poll/2` re-reads inside the store's serialized transition, so a concurrent
  # approval or denial is not clobbered; its status is resolved by this call.
  defp poll(trusted, spec) do
    case spec.store.poll(spec.key, spec.poll_args) do
      {:ok, polled} when is_map(polled) and is_map_key(polled, :status) ->
        accept_poll(trusted, polled, spec)

      {:error, :slow_down} ->
        {:error, :slow_down}

      # Vanished between the read and the poll (e.g. swept): treat as unknown.
      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        spec.contract_error.(:poll)
    end
  end

  defp accept_poll(trusted, polled, spec) do
    if spec.poll_transition?.(trusted, polled) do
      with :ok <- spec.after_poll.(polled), do: resolve_polled(polled, spec)
    else
      spec.contract_error.(:poll)
    end
  end

  defp resolve_polled(%{status: :pending}, _spec), do: {:error, :authorization_pending}
  defp resolve_polled(%{status: :approved} = polled, spec), do: consume(polled, spec)
  defp resolve_polled(%{status: :denied}, _spec), do: {:error, :access_denied}
  defp resolve_polled(%{status: :consumed}, _spec), do: {:error, :invalid_grant}

  defp consume(trusted, spec) do
    case spec.store.consume(spec.key, %{now: spec.now}) do
      {:ok, consumed} when is_map(consumed) and is_map_key(consumed, :status) ->
        if spec.consume_transition?.(trusted, consumed),
          do: {:ok, spec.to_grant.(consumed)},
          else: spec.contract_error.(:consume)

      # Lost the consume race (a concurrent token request consumed it), or the
      # status or expiry moved between poll and consume.
      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        spec.contract_error.(:consume)
    end
  end
end
