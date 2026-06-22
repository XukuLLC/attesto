defmodule Attesto.RefreshToken do
  @moduledoc """
  Refresh-token issuance and rotation with reuse detection
  (RFC 6749 §6 / §10.4, OAuth 2.0 Security BCP).

  Each refresh token is single-use: presenting it (`rotate/3`) consumes it
  and mints a successor in the same *family*. A short idempotency window
  (10 seconds by default) lets the same client retry the just-consumed
  parent after a lost response and receive the same successor. Outside
  that window, or when the retry does not match the original client,
  binding, and scope, a rotated token is a captured-token signal and the
  entire family is revoked so neither the attacker nor the victim can
  continue, forcing a fresh authorization.

  This module is pure logic over a `Attesto.RefreshStore`; the store
  provides the atomic `consume/1` on which reuse detection depends (see
  that behaviour's moduledoc). Only the hash of each token is stored.

  ## DPoP binding

  A refresh token can be bound to a DPoP key (its issuing context carries
  a `:dpop_jkt`). Rotation then requires the caller to present the
  matching `:dpop_jkt` (the thumbprint of the key in the token-request's
  DPoP proof); an unbound token must be rotated without one. The binding
  matrix mirrors `Attesto.Token` and `Attesto.AuthorizationCode`.
  """

  alias Attesto.Scope
  alias Attesto.Secret
  alias Attesto.Thumbprint

  # 14 days. Refresh lifetime is a host policy; this is a sane default.
  @default_ttl_seconds 14 * 24 * 60 * 60

  @type context :: %{
          required(:subject) => String.t(),
          optional(:scope) => [String.t()],
          optional(:resource) => [String.t()],
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

  @type issue_error :: :invalid_subject | :invalid_scope | :invalid_dpop_jkt | :invalid_claims | :family_revoked

  @type rotate_error ::
          :invalid_grant
          | :reuse_detected
          | :expired
          | :client_required
          | :client_mismatch
          | :invalid_scope
          | :dpop_proof_required
          | :dpop_proof_unexpected
          | :dpop_binding_mismatch

  @doc """
  Issue a refresh token for `context` and persist it via `store`.

  `context` MUST carry `:subject`; optional `:scope` (list, default
  `[]`), `:client_id`, `:dpop_jkt` (binds the token to a DPoP key), and
  `:claims` (opaque host context).

  Options: `:ttl` (seconds, default 14 days), `:now`, and - when
  continuing a family during rotation - `:family_id` and `:generation`
  (callers issuing a first token omit both: a fresh family is started at
  generation 0).

  Returns `{:ok, %{token, family_id, generation}}` with the plaintext
  token to hand the client (only its hash is stored), or
  `{:error, reason}` on malformed `context`. Returns
  `{:error, :family_revoked}` only when continuing an explicit
  `:family_id` that has been revoked (a fresh first issue starts a new
  family and never hits this).
  """
  @spec issue(module(), context(), keyword()) :: {:ok, issued()} | {:error, issue_error()}
  def issue(store, context, opts \\ []) when is_atom(store) and is_map(context) and is_list(opts) do
    with {:ok, data} <- normalize_context(context) do
      token = Secret.generate()
      family_id = Keyword.get_lazy(opts, :family_id, fn -> Secret.generate(16) end)
      generation = Keyword.get(opts, :generation, 0)
      ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)

      case store.insert(%{
             token_hash: Secret.hash(token),
             family_id: family_id,
             generation: generation,
             data: data,
             expires_at: unix_now(opts) + ttl,
             consumed: false,
             consumed_at: nil,
             successor: nil
           }) do
        :ok -> {:ok, %{token: token, family_id: family_id, generation: generation}}
        {:error, :family_revoked} = err -> err
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
  returned. Other failures: `:invalid_grant` (unknown token), `:expired`,
  `:client_mismatch`, `:invalid_scope`, and the DPoP binding errors.

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
    * `:rotation_grace_seconds` - idempotency window for an immediate retry of
      the just-rotated token. Defaults to `10`; set `0` for strict reuse
      revocation.

  Recoverable failures (`:client_mismatch`, `:invalid_scope`, `:expired`,
  the DPoP binding errors) are checked on a non-consuming read *before*
  the token is claimed, so they do NOT burn the token: a client that, say,
  retries with a corrected DPoP proof succeeds rather than tripping reuse
  detection. Only a genuine replay of an already-consumed token (or a
  concurrent double-claim) revokes the family.
  """
  @spec rotate(module(), String.t(), keyword()) :: {:ok, rotated()} | {:error, rotate_error()}
  def rotate(store, presented_token, opts \\ []) when is_atom(store) and is_binary(presented_token) and is_list(opts) do
    case store.get(Secret.hash(presented_token)) do
      {:ok, %{consumed: true} = record} ->
        maybe_idempotent_retry_or_reuse(store, record, opts)

      {:ok, %{consumed: false} = record} ->
        rotate_unconsumed(store, record, opts)

      :error ->
        {:error, :invalid_grant}
    end
  end

  defp maybe_idempotent_retry_or_reuse(store, record, opts) do
    with true <- within_rotation_grace?(record, opts),
         :ok <- check_client(record.data, opts),
         :ok <- check_dpop(record.data, opts),
         {:ok, scope} <- resolve_scope(record.data, opts),
         {:ok, successor} <- same_successor(record, scope),
         :ok <- successor_still_live?(store, successor) do
      {:ok,
       %{
         token: successor.token,
         family_id: record.family_id,
         generation: successor.generation,
         context: successor.context
       }}
    else
      _ ->
        :ok = store.revoke_family(record.family_id)
        {:error, :reuse_detected}
    end
  end

  # OAuth 2.0 Security BCP §4.13.2: the rotation-grace idempotent retry is safe
  # ONLY while the cached successor is itself still the live, unconsumed leaf -
  # i.e. the client genuinely lost the original rotation response and never used
  # the successor. If the successor has since been rotated (consumed) or is gone,
  # the chain has demonstrably advanced past it, so replaying the parent is a
  # true reuse of an already-used token, not a lost-response retry: fall through
  # to family revocation rather than re-issuing the (now stale) successor.
  defp successor_still_live?(store, successor) do
    case store.get(Secret.hash(successor.token)) do
      {:ok, %{consumed: false}} -> :ok
      _ -> {:error, :successor_consumed}
    end
  end

  # Validate on the read (no consumption), then atomically claim. Only the
  # claim consumes the token, so a recoverable validation failure leaves
  # it intact for a corrected retry.
  defp rotate_unconsumed(store, record, opts) do
    with :ok <- check_client(record.data, opts),
         :ok <- check_expiry(record, opts),
         :ok <- check_dpop(record.data, opts),
         {:ok, scope} <- resolve_scope(record.data, opts),
         {:ok, claimed} <- claim(store, record, opts) do
      issue_successor(store, claimed, scope, opts)
    end
  end

  defp issue_successor(store, claimed, scope, opts) do
    successor_data = %{claimed.data | scope: scope}

    case issue(store, successor_data,
           family_id: claimed.family_id,
           generation: claimed.generation + 1,
           ttl: Keyword.get(opts, :ttl, @default_ttl_seconds),
           now: Keyword.get(opts, :now)
         ) do
      {:ok, issued} ->
        _ =
          store.remember_successor(
            claimed.token_hash,
            %{
              token: issued.token,
              generation: issued.generation,
              context: successor_data
            },
            now: unix_now(opts)
          )

        {:ok,
         %{
           token: issued.token,
           family_id: issued.family_id,
           generation: issued.generation,
           context: successor_data
         }}

      {:error, :family_revoked} ->
        # We won the atomic claim, but a concurrent reuse revoked the family
        # before our successor landed: a concurrent double-use. Ensure the
        # family is revoked and report it as reuse, not a fresh token.
        :ok = store.revoke_family(claimed.family_id)
        {:error, :reuse_detected}
    end
  end

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

  defp allow_missing_client?(opts), do: Keyword.get(opts, :allow_missing_client_id?, false)

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

  # The atomic claim. Closes the read-then-claim race: if a concurrent
  # rotation claimed this token between our read and here, `consume`
  # reports `{:reuse, _}` and we revoke the family.
  defp claim(store, record, opts) do
    case store.consume(record.token_hash, now: unix_now(opts)) do
      {:ok, claimed} ->
        {:ok, claimed}

      {:reuse, claimed} ->
        :ok = store.revoke_family(claimed.family_id)
        {:error, :reuse_detected}

      :error ->
        {:error, :invalid_grant}
    end
  end

  defp within_rotation_grace?(record, opts) do
    grace = Keyword.get(opts, :rotation_grace_seconds, 10)
    consumed_at = Map.get(record, :consumed_at)

    is_integer(grace) and grace > 0 and is_integer(consumed_at) and
      unix_now(opts) - consumed_at <= grace
  end

  defp same_successor(record, scope) do
    case Map.get(record, :successor) do
      %{token: token, generation: generation, context: %{scope: ^scope} = context}
      when is_binary(token) and is_integer(generation) ->
        {:ok, %{token: token, generation: generation, context: context}}

      _ ->
        {:error, :no_successor}
    end
  end

  # ----- validation -----

  defp normalize_context(context) do
    scope = Map.get(context, :scope, [])
    resource = Map.get(context, :resource, [])
    dpop_jkt = Map.get(context, :dpop_jkt)

    cond do
      not non_empty_binary?(Map.get(context, :subject)) -> {:error, :invalid_subject}
      not valid_scope?(scope) -> {:error, :invalid_scope}
      not valid_resource?(resource) -> {:error, :invalid_resource}
      not valid_optional_jkt?(dpop_jkt) -> {:error, :invalid_dpop_jkt}
      not is_map(Map.get(context, :claims, %{})) -> {:error, :invalid_claims}
      # RFC 8707: the bound resource set rides through rotation unchanged via the
      # `%{claimed.data | scope: scope}` struct-update in `issue_successor/4`, so
      # a refreshed access token stays audienced to the same resource(s).
      true -> {:ok, build_data(context, scope, resource, dpop_jkt)}
    end
  end

  defp build_data(context, scope, resource, dpop_jkt) do
    %{
      subject: context.subject,
      scope: scope,
      resource: resource,
      client_id: Map.get(context, :client_id),
      dpop_jkt: dpop_jkt,
      claims: Map.get(context, :claims, %{})
    }
  end

  defp check_expiry(%{expires_at: expires_at}, opts) do
    if expires_at > unix_now(opts), do: :ok, else: {:error, :expired}
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
  defp valid_scope?(scope), do: is_list(scope) and Enum.all?(scope, &Scope.valid_token?/1)
  defp valid_resource?(resource), do: is_list(resource) and Enum.all?(resource, &non_empty_binary?/1)
  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(jkt), do: Thumbprint.valid?(jkt)

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end
end
