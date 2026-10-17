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

  `:ttl` bounds inactivity between refreshes. An optional `:family_ttl` on
  initial issuance also fixes an absolute family deadline, which every
  successor inherits. Rotation and lost-response retries cannot extend it
  (RFC 10017 §6.3.2.3).

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

  An attested client's verified Client Instance Key is bound independently as
  `:attestation_jkt`. Every rotation and retry requires that same instance key,
  even when its DPoP key differs. An unbound legacy token rejects a presented
  instance key; its original binding cannot be reconstructed after issuance.

  ## Issuer binding

  A host that may share a refresh store across authorization-server issuers can
  pass the issuing server's exact `:issuer` in the initial context. Passing
  that server's identifier as the `:issuer` option to `rotate/3` then requires
  an exact match before an unconsumed token can be claimed. If the caller
  supplies an expected issuer for a legacy token that has no issuer binding,
  rotation fails closed with `:issuer_mismatch` and leaves the token usable by
  a caller applying the correct legacy policy. Omitting the option preserves
  compatibility for existing callers and families.

  The marker is stored under a core-reserved string key inside `:claims`, so
  stores that serialize this established JSON field preserve it without a
  schema migration. Host claims cannot set that key. Returned rotation context
  exposes the verified value as top-level `:issuer` and removes the reserved
  entry before handing `:claims` back to the host.
  """

  alias Attesto.NumericDate
  alias Attesto.Options
  alias Attesto.RefreshToken.Record, as: TokenRecord
  alias Attesto.RefreshToken.Rotation
  alias Attesto.Store

  # 14 days. Refresh lifetime is a host policy; this is a sane default.
  @default_ttl_seconds 14 * 24 * 60 * 60

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
          optional(:issuer) => String.t(),
          optional(:dpop_jkt) => String.t() | nil,
          optional(:attestation_jkt) => String.t() | nil,
          optional(:claims) => map()
        }

  @type issued :: %{
          token: String.t(),
          family_id: String.t(),
          generation: non_neg_integer(),
          expires_at: non_neg_integer()
        }

  @type rotated :: %{
          token: String.t(),
          family_id: String.t(),
          generation: non_neg_integer(),
          expires_at: non_neg_integer(),
          context: map()
        }

  @type issue_error ::
          :invalid_subject
          | :invalid_scope
          | :invalid_resource
          | :invalid_client_id
          | :invalid_issuer
          | :invalid_dpop_jkt
          | :invalid_attestation_jkt
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
          | :issuer_mismatch
          | :invalid_scope
          | :invalid_target
          | :dpop_proof_required
          | :dpop_proof_unexpected
          | :dpop_binding_mismatch
          | :attestation_proof_required
          | :attestation_proof_unexpected
          | :attestation_binding_mismatch

  @doc """
  Issue a refresh token for `context` and persist it via `store`.

  `context` MUST carry `:subject`; optional `:scope` (list, default
  `[]`), `:client_id`, `:issuer` (the exact authorization-server issuer),
  `:dpop_jkt` (binds the token to a DPoP key),
  `:attestation_jkt` (the verified Client Instance Key), and
  `:claims` (a lossless, string-keyed I-JSON object of host context; persisted
  numbers are exact-range integers, not floats).

  Options: `:ttl` (idle seconds, default 14 days), `:family_ttl` (optional
  positive seconds, fixing the entire family's maximum lifetime), and `:now`.
  The family deadline is stored as `:family_expires_at` in the canonical
  context and caps the initial token as well as every successor. Public issuance
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

    with {:ok, normalized} <- TokenRecord.normalize_context(context) do
      data = put_family_deadline(normalized, opts)

      case persist_issue(store, data, opts) do
        {:ok, issued} -> {:ok, issued}
        {:error, :family_revoked} = error -> error
        {:store_contract_violation} -> Store.contract_violation!("refresh store", {:insert, 1})
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
  `:issuer_mismatch`, `:invalid_scope`, and the DPoP binding errors.

  Options:

    * `:now` - clock override.
    * `:dpop_jkt` - the presented proof's thumbprint (for DPoP-bound
      tokens).
    * `:attestation_jkt` - the authenticated Client Instance Key thumbprint,
      required for an attestation-bound family independently of its DPoP key.
    * `:client_id` - the authenticated presenting client. When the token
      was issued with a `client_id`, rotation is fail-closed: it MUST
      present a matching one (`:client_required` if absent,
      `:client_mismatch` if wrong), closing token substitution across
      clients (RFC 6749 §6 / §10.4). Pass `allow_missing_client_id?: true`
      to opt out. A token issued without a client binding skips the check.
    * `:issuer` - the authorization server expected to have issued this
      refresh family. When supplied, it must exactly match the bounded HTTPS
      issuer saved at issuance. A different issuer, or a legacy token with no
      issuer binding, returns `:issuer_mismatch` without consuming an
      unconsumed token or revoking a consumed token's family. Omitting this
      option preserves legacy behavior.
    * `:scope` - a requested scope list. MUST be a subset of the token's
      granted scope; the successor then carries the narrowed scope. A
      request for any scope not granted is `:invalid_scope` (no
      escalation). Omitted, the successor carries the full granted scope.
    * `:ttl` - lifetime for the successor.
    * `:rotation_grace_seconds` - non-negative integer idempotency window for
      an immediate retry of the just-rotated token. Defaults to `10`; set `0`
      for strict reuse revocation. The window is fixed when the successor is
      issued: a later call may shorten it, but cannot extend it.

  Recoverable failures (`:client_mismatch`, `:issuer_mismatch`,
  `:invalid_scope`, `:expired`, the DPoP binding errors) are checked on a
  non-consuming read *before* the token is claimed, so they do NOT burn the
  token: a client that, say, retries with a corrected DPoP proof succeeds
  rather than tripping reuse detection. Issuer mismatch is also checked before
  retry/reuse handling for an already-consumed token, so a request routed to a
  different issuer cannot revoke the legitimate issuer's family. An
  already-consumed token is accepted only when its complete successor state
  proves it is the same request inside the fixed retry window.

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
  defdelegate rotate(store, presented_token, opts \\ []), to: Rotation

  @doc false
  @spec issuer_matches?(map(), term()) :: boolean()
  defdelegate issuer_matches?(data, expected), to: TokenRecord

  @doc false
  @spec valid_issuer_binding?(map()) :: boolean()
  defdelegate valid_issuer_binding?(data), to: TokenRecord

  defp persist_issue(store, data, opts), do: persist_issue(store, data, opts, 3)

  defp persist_issue(store, data, opts, attempts_left) do
    {issued, record} = TokenRecord.build_issue(data, opts, @default_ttl_seconds)

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

  defp call_store_callback(callback) do
    {:returned, callback.()}
  catch
    kind, value -> {:failed, kind, value, __STACKTRACE__}
  end

  defp validate_issue_options!(opts) do
    _ttl = ttl_seconds!(opts)
    _family_ttl = family_ttl_seconds!(opts)
    _now = refresh_now!(opts)

    if Keyword.has_key?(opts, :family_id) or Keyword.has_key?(opts, :generation) do
      raise ArgumentError,
            ":family_id and :generation are internal rotation state; public issuance always starts a new family"
    end

    :ok
  end

  defp family_ttl_seconds!(opts), do: Options.optional_positive_integer!(opts, :family_ttl)

  defp put_family_deadline(data, opts) do
    case family_ttl_seconds!(opts) do
      nil -> data
      ttl -> Map.put(data, :family_expires_at, refresh_now!(opts) + ttl)
    end
  end

  defp ttl_seconds!(opts), do: Options.positive_integer!(opts, :ttl, @default_ttl_seconds)

  defp refresh_now!(opts), do: NumericDate.non_negative_now!(opts, invalid_override: :non_negative)
end
