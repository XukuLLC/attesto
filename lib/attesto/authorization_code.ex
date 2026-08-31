defmodule Attesto.AuthorizationCode do
  @moduledoc """
  RFC 6749 §4.1 authorization-code grant, with mandatory PKCE (RFC 7636,
  S256) and optional DPoP binding of the code (RFC 9449 §10).

  This module is pure logic over a `Attesto.CodeStore`: `issue/3` mints a
  single-use code at the authorization endpoint, `redeem/4` validates and
  consumes it at the token endpoint and returns the grant context the host
  uses to mint an access token. The store decides where codes live and
  guarantees single use; everything validated here (expiry, exact
  redirect-URI match, the PKCE transform, the DPoP key binding) is
  protocol.

  ## PKCE (S256), required by default

  `issue/3` accepts a valid S256 `code_challenge` and `redeem/4` checks the
  matching `code_verifier`; only S256 is accepted (see `Attesto.PKCE`). This
  closes authorization-code interception and is the modern default (OAuth 2.0
  Security BCP / RFC 9700). PKCE enforcement at the authorization endpoint is
  governed by `Attesto.AuthorizationRequest`'s `:require_pkce` option (default
  `true`); a host MAY relax it for a *confidential* client (public clients MUST
  use PKCE, RFC 9700 §2.1.1), in which case a code is issued with no challenge
  and redeemed with no verifier. A `code_challenge` that is present is always
  fully enforced. `issue/3` therefore treats `:code_challenge` as optional: when
  given it must be a valid S256 challenge, when absent the code is unbound and a
  later redemption MUST present no `code_verifier`.

  ## Single use even on failure

  `redeem/4` consumes the code via `c:Attesto.CodeStore.take/1` **before**
  validating it, so a presented code is spent whether or not the
  redemption succeeds. An attacker who captures a code cannot make
  repeated validation attempts against it.

  ## Code-reuse detection (when the store supports it)

  Single use alone cannot distinguish a *replay of an already-redeemed
  code* from a *never-issued code*: once `take/1` removes the row, both
  look absent. OAuth 2.0 Security BCP §4.13 (and RFC 6749 §4.1.2) say the
  AS SHOULD, on a second presentation of a code, revoke the tokens already
  issued from its first redemption, because a re-presented code is an
  attack signal.

  `redeem/4` enables that when - and only when - the `Attesto.CodeStore`
  implements the optional reuse-tracking pair (`c:Attesto.CodeStore.take/1`
  returning `{:error, :consumed, meta}` plus
  `c:Attesto.CodeStore.mark_consumed/2`). The reuse marker is recorded by
  `finalize/3`, which the caller invokes AFTER all access-token, ID-token, and
  other response fields have been successfully built - NOT by `redeem/4`
  itself. So a code whose redemption
  validated but whose downstream issuance then failed (a mint or refresh-token
  fault, a host callback returning a bad principal) is left single-use-spent
  but NOT reuse-flagged: a replay is `{:error, :invalid_grant}`, and a
  legitimate retry of a transient failure is never mistaken for a reuse attack
  (which would wrongly revoke the family). Once `finalize/3` has run, a later
  redemption of the same code yields `{:error, {:reuse, meta}}`, where `meta`
  carries that first redemption's context so the caller can revoke the
  descendant family (e.g. via `Attesto.Revocation`). The no-refresh
  `finalize/3` path records a nil family ID; only
  `issue_refresh_and_finalize/6` records the exact family returned by refresh
  issuance. A store that does not
  implement the pair behaves exactly as before: a re-presented code is
  `{:error, :invalid_grant}`.
  This is additive and fail-safe (see `Attesto.CodeStore`).

  `:family_id` on an authorization request is provenance metadata carried by
  the returned `Grant`; public `Attesto.RefreshToken.issue/3` deliberately
  rejects that value and always creates a fresh family. A host that issues a
  refresh token from a redeemed code should use
  `issue_refresh_and_finalize/6`, which owns issuance, captures the returned
  family ID, and records it only after issuance succeeds. This keeps the
  code-reuse marker useful without reopening caller control over
  refresh-family generation. That helper also requires the refresh context's
  subject and client to match the redeemed grant and permits only
  scope/resource narrowing.

  RFC 9449 §5 requires a public client's refresh token to be DPoP-bound and
  prohibits binding a confidential client's refresh token. The host knows the
  client classification and must choose the refresh context's `:dpop_jkt`
  accordingly; core cannot infer it. For a DPoP-bound grant,
  `issue_refresh_and_finalize/6` therefore permits either `nil` (confidential
  refresh) or the grant's exact JKT (public refresh), and rejects any other
  JKT. For an unbound grant, the host may still select a token-endpoint DPoP
  binding as described below.

  ## DPoP-bound codes

  If `issue/3` is given a `:dpop_jkt`, the code is bound to that DPoP key
  (RFC 9449 §10): redemption MUST present the same `:dpop_jkt` (the
  thumbprint of the key in the token-request's DPoP proof) or it is
  rejected. A code minted without a binding MAY still be redeemed while a
  token-request DPoP proof is present - this module does not reject that
  (unlike `Attesto.RefreshToken`, which is stricter). But it does NOT act on
  that proof: the returned grant's `dpop_jkt` stays `nil`, and binding the
  new access token to the token-request proof is the token endpoint's job
  (via `Attesto.Token`'s `:dpop_jkt` mint opt), not this module's. A host
  that decides the new token's binding from `grant.dpop_jkt` alone would
  therefore miss a token-endpoint proof; read the presented proof directly.
  """

  alias Attesto.AuthorizationCode.Grant
  alias Attesto.NumericDate
  alias Attesto.PKCE
  alias Attesto.Scope
  alias Attesto.Secret
  alias Attesto.Thumbprint

  @default_ttl_seconds 60
  @canonical_data_keys [
    :client_id,
    :code_challenge,
    :claims,
    :dpop_jkt,
    :family_id,
    :redirect_uri,
    :resource,
    :scope,
    :subject
  ]

  @type issue_attrs :: %{
          required(:client_id) => String.t(),
          required(:redirect_uri) => String.t(),
          optional(:code_challenge) => String.t() | nil,
          required(:subject) => String.t(),
          optional(:scope) => [String.t()],
          optional(:resource) => [String.t()],
          optional(:code_challenge_method) => String.t(),
          optional(:dpop_jkt) => String.t() | nil,
          optional(:family_id) => String.t() | nil,
          optional(:claims) => map()
        }

  @type issue_error ::
          :invalid_client_id
          | :invalid_redirect_uri
          | :invalid_code_challenge
          | :unsupported_code_challenge_method
          | :invalid_subject
          | :invalid_scope
          | :invalid_resource
          | :invalid_dpop_jkt
          | :invalid_family_id
          | :invalid_claims

  @type redeem_params :: %{
          required(:redirect_uri) => String.t(),
          required(:code_verifier) => String.t(),
          optional(:client_id) => String.t(),
          optional(:dpop_jkt) => String.t() | nil
        }

  @type redeem_error ::
          :invalid_grant
          | :expired
          | :client_required
          | :client_mismatch
          | :redirect_uri_mismatch
          | :pkce_failed
          | :dpop_proof_required
          | :dpop_binding_mismatch
          | {:reuse, Attesto.CodeStore.consumed_meta()}

  @doc """
  Mint a single-use authorization code and persist it via `store`.

  `attrs` MUST carry `:client_id`, `:redirect_uri`, and `:subject`.
  Optional `:code_challenge` binds the code to PKCE; when present,
  `:code_challenge_method` must be `"S256"` if given. Optional `:scope` (a
  list of strings, default `[]`), `:dpop_jkt` (binds the code to a DPoP key),
  `:family_id` (a non-empty provenance string round-tripped to the redeemed
  `Grant`; use `issue_refresh_and_finalize/6` to bind the actually issued
  refresh family), and
  `:claims` (an opaque host context map
  round-tripped to `redeem/4`).

  Options: `:ttl` (seconds the code is valid, default
  #{@default_ttl_seconds}) and `:now` (clock override).

  Returns `{:ok, code}` with the plaintext code to hand the client. Only
  the code's hash is stored. Returns `{:error, reason}` on malformed
  `attrs`.
  """
  @spec issue(module(), issue_attrs(), keyword()) :: {:ok, String.t()} | {:error, issue_error()}
  def issue(store, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    with :ok <- validate_method(attrs),
         {:ok, data} <- normalize_issue_attrs(attrs) do
      ttl = ttl_seconds!(opts)
      now = NumericDate.non_negative_now!(opts)
      code = Secret.generate()

      case store.put(%{
             code_hash: Secret.hash(code),
             data: data,
             expires_at: now + ttl
           }) do
        :ok -> {:ok, code}
        _unexpected -> code_store_contract_error(:put)
      end
    end
  end

  defp ttl_seconds!(opts) do
    case Keyword.get(opts, :ttl, @default_ttl_seconds) do
      ttl when is_integer(ttl) and ttl > 0 -> ttl
      _invalid -> raise ArgumentError, ":ttl must be a positive integer"
    end
  end

  @doc """
  Validate and consume a code at the token endpoint.

  `params` MUST carry the `:redirect_uri` (matched exactly against the one
  in the authorization request), the `:code_verifier` (checked against the
  stored PKCE challenge), and the `:client_id` of the redeeming client. By
  default client binding is fail-closed: since every stored code carries a
  `client_id`, redemption MUST present one (`:client_required` if absent,
  `:client_mismatch` if wrong) - this stops a code issued to one client
  being redeemed by another (RFC 6749 §4.1.3). A caller that cannot
  authenticate the client and relies on PKCE alone passes
  `allow_missing_client_id?: true` in `opts`. `:dpop_jkt` is required iff
  the code was DPoP-bound at `issue/3`; if the code was not bound, a presented
  `:dpop_jkt` is allowed and can be used by the caller to mint a DPoP-bound
  access token.

  The code is consumed (single use) before validation. Returns
  `{:ok, %Attesto.AuthorizationCode.Grant{}}` with the validated grant
  context, or `{:error, reason}`.

  When the `store` implements optional reuse tracking (see
  `Attesto.CodeStore`), a second redemption of a code that was already
  successfully redeemed returns `{:error, {:reuse, meta}}` rather than
  `{:error, :invalid_grant}`. `meta` carries the first redemption's
  `:family_id` and `:subject`. For a redemption that issued a refresh token,
  `:family_id` identifies the descendant family to revoke (OAuth 2.0 Security
  BCP §4.13); for a no-refresh redemption it is `nil`. Codes the store has
  never seen remain `{:error, :invalid_grant}`.
  """
  @spec redeem(module(), String.t(), redeem_params(), keyword()) ::
          {:ok, Grant.t()} | {:error, redeem_error()}
  def redeem(store, code, params, opts \\ [])
      when is_atom(store) and is_binary(code) and is_map(params) and is_list(opts) do
    now = NumericDate.non_negative_now!(opts)
    _allow_missing_client = allow_missing_client?(opts)
    opts = Keyword.put(opts, :now, now)
    code_hash = Secret.hash(code)

    case store.take(code_hash) do
      {:ok, record} ->
        if valid_record?(record, code_hash),
          do: redeem_taken(record, params, opts),
          else: code_store_contract_error(:take)

      # OAuth 2.0 Security BCP §4.13 / RFC 6749 §4.1.2: a re-presented,
      # already-FINALIZED code is the reuse attack signal. Only stores with
      # reuse tracking return this, and only once finalization has recorded the
      # marker; surface the first redemption's context so the caller can revoke
      # the descendant family.
      {:error, :consumed, meta} when is_map(meta) ->
        {:error, {:reuse, meta}}

      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        code_store_contract_error(:take)
    end
  end

  @doc """
  Returns `true` iff a stored code for `code` is bound to a DPoP key (RFC 9449
  §10) - i.e. its redemption requires a matching DPoP proof (holder-of-key).

  Reads the code via the store's OPTIONAL `c:Attesto.CodeStore.get/1` WITHOUT
  consuming it, so a legitimate redemption is unaffected. Returns `false` when
  the store has no `get/1`, the code is unknown, or it carries no `:dpop_jkt`.
  This lets the token endpoint surface a holder-of-key (`invalid_dpop_proof`)
  rejection ahead of the client-authentication error (FAPI2) without burning the
  single-use code.
  """
  @spec dpop_bound?(module(), String.t()) :: boolean()
  def dpop_bound?(store, code) when is_atom(store) and is_binary(code) do
    if function_exported?(store, :get, 1) do
      read_dpop_binding(store, Secret.hash(code))
    else
      false
    end
  end

  defp read_dpop_binding(store, code_hash) do
    case store.get(code_hash) do
      {:ok, record} -> dpop_binding_from_record(record, code_hash)
      :error -> false
      _unexpected -> code_store_contract_error(:get)
    end
  end

  defp dpop_binding_from_record(%{code_hash: code_hash, data: data, expires_at: expires_at}, code_hash)
       when is_map(data) and is_integer(expires_at) do
    case Map.get(data, :dpop_jkt) do
      jkt when is_binary(jkt) and jkt != "" -> true
      nil -> false
      _malformed -> code_store_contract_error(:get)
    end
  end

  defp dpop_binding_from_record(_record, _code_hash), do: code_store_contract_error(:get)

  # `take/1` has already claimed the code (single use). Validate it and return
  # the grant. The reuse marker is NOT recorded here - the caller records it via
  # `finalize/3` only after the full token response is built, so a downstream
  # issuance failure leaves the code spent-but-unfinalized (a replay is
  # `:invalid_grant`, never a false reuse).
  defp redeem_taken(%{data: data, expires_at: expires_at}, params, opts) do
    with :ok <- check_expiry(expires_at, opts),
         :ok <- check_client(data, params, opts),
         :ok <- check_redirect_uri(data, params),
         :ok <- check_pkce(data, params),
         :ok <- check_dpop(data, params) do
      {:ok, Grant.from_data(data)}
    end
  end

  @doc """
  Finalize a fully completed redemption: record the reuse marker
  (`consumed_success`) for `code`'s grant.

  Call this only AFTER the full token response has been successfully built. It
  is split from `redeem/4` so redemption is atomic - `redeem/4` claims the code
  (single use, via `take/1`) and validates it, but defers this marker so a
  failure in the caller's downstream issuance (mint, refresh-token persistence,
  a host callback fault) does NOT leave a spent-but-tokenless code recorded as a
  completed redemption (which would make a legitimate retry look like a reuse
  attack and revoke the family). A no-op for stores that do not implement
  `c:Attesto.CodeStore.mark_consumed/2`. This form is only for flows that issue
  no refresh token and always records a nil `family_id` in the marker. The
  `Grant`'s `family_id` is authorization provenance, not a refresh-family
  identifier. For a refresh grant, use `issue_refresh_and_finalize/6` so the
  marker carries the family ID returned by `RefreshToken.issue/3` without
  accepting a caller-supplied ID.
  """
  @spec finalize(module(), String.t(), Grant.t()) :: :ok
  def finalize(store, code, %Grant{} = grant) when is_atom(store) and is_binary(code) do
    # An authorization-request family is provenance only. A no-refresh marker
    # must never be mistaken for the family of a refresh credential.
    record_consumption(store, Secret.hash(code), %{grant | family_id: nil})
  end

  @doc """
  Issue an initial refresh token for a redeemed code and finalize its reuse
  marker with the family ID returned by the refresh-token issuer.

  This composition API is the safe bridge for authorization-code flows that
  issue refresh tokens. First finish every access-token, ID-token, and other
  response operation that can fail; then call this function, and add the
  returned plaintext refresh token to the response only after it returns
  `{:ok, issued}`. It calls `Attesto.RefreshToken.issue/3` itself, so callers
  never provide a family ID or generation. Only a validated success result can
  reach `mark_consumed/2`, and the exact family ID captured from that result is
  written to the code-reuse marker. A refresh issuance error is returned
  unchanged and leaves the code spent-but-unfinalized. A finalization exception
  or contract violation is propagated and never becomes an `:ok` result.

  `refresh_context` must carry the redeemed grant's `:subject` and
  `:client_id`, and its `:scope` and `:resource` lists must be subsets of the
  grant's authorization. If the redeemed grant is DPoP-bound, the context's
  `:dpop_jkt` may be `nil` for a confidential-client refresh or must exactly
  match that binding for a public-client refresh; a different key is rejected.
  The host is responsible for that public/confidential classification and for
  choosing the context binding required by RFC 9449 §5. A token-endpoint DPoP
  binding may differ from the authorization-request binding only when the
  redeemed grant itself is unbound, which permits token-endpoint DPoP
  initiation without weakening a holder-of-key grant. The context must not
  contain top-level `:family_id` or `:generation` continuation fields. Those
  are internal rotation state, not caller input; put authorization provenance
  inside `:claims` when needed.
  """
  @spec issue_refresh_and_finalize(
          module(),
          String.t(),
          Grant.t(),
          module(),
          Attesto.RefreshToken.context(),
          keyword()
        ) :: {:ok, Attesto.RefreshToken.issued()} | {:error, Attesto.RefreshToken.issue_error()}
  def issue_refresh_and_finalize(code_store, code, %Grant{} = grant, refresh_store, refresh_context, opts \\ [])
      when is_atom(code_store) and is_binary(code) and is_atom(refresh_store) and is_map(refresh_context) and
             is_list(opts) do
    validate_refresh_context!(grant, refresh_context)

    case Attesto.RefreshToken.issue(refresh_store, refresh_context, opts) do
      {:ok, issued} ->
        issued = validate_issued_refresh!(issued)
        :ok = record_consumption(code_store, Secret.hash(code), %{grant | family_id: issued.family_id})
        {:ok, issued}

      {:error, _reason} = error ->
        error
    end
  end

  defp validate_refresh_context!(%Grant{} = grant, context) do
    if not valid_refresh_grant?(grant) do
      raise ArgumentError, "redeemed grant is invalid for refresh-token issuance"
    end

    if Enum.any?([:family_id, :generation, "family_id", "generation"], &Map.has_key?(context, &1)) do
      raise ArgumentError,
            ":family_id and :generation are internal refresh rotation state and are not valid issue context fields"
    end

    require_matching_context!(context, :subject, grant.subject)
    require_matching_context!(context, :client_id, grant.client_id)
    require_subset_context!(context, :scope, grant.scope)
    require_subset_context!(context, :resource, grant.resource)

    if not is_nil(grant.dpop_jkt) do
      require_optional_matching_context!(context, :dpop_jkt, grant.dpop_jkt)
    end

    :ok
  end

  defp valid_refresh_grant?(%Grant{} = grant) do
    non_empty_binary?(grant.client_id) and non_empty_binary?(grant.redirect_uri) and
      non_empty_binary?(grant.subject) and valid_scope?(grant.scope) and
      valid_resource?(grant.resource) and valid_optional_jkt?(grant.dpop_jkt) and
      valid_optional_family_id?(grant.family_id) and is_map(grant.claims)
  end

  defp require_matching_context!(context, key, expected) do
    if Map.get(context, key) != expected do
      raise ArgumentError, "refresh context :#{key} must match the redeemed grant"
    end
  end

  defp require_optional_matching_context!(context, key, expected) do
    case Map.get(context, key) do
      nil -> :ok
      ^expected -> :ok
      _different -> raise ArgumentError, "refresh context :#{key} must match the redeemed grant"
    end
  end

  defp require_subset_context!(context, key, granted) do
    requested = Map.get(context, key, [])

    if not is_list(requested) or not Enum.all?(requested, &(&1 in granted)) do
      raise ArgumentError, "refresh context :#{key} must be a subset of the redeemed grant"
    end
  end

  defp validate_issued_refresh!(%{token: token, family_id: family_id, generation: generation} = issued)
       when is_binary(token) and token != "" and is_binary(family_id) and family_id != "" and is_integer(generation) and
              generation == 0 do
    issued
  end

  defp validate_issued_refresh!(_invalid) do
    raise RuntimeError, "refresh token issue/3 violated its contract"
  end

  # Record the successful redemption so a re-presentation of the same code
  # is detectable as reuse (OAuth 2.0 Security BCP §4.13). Only stores that
  # implement the optional `mark_consumed/2` callback get the marker; the
  # absence of the callback leaves single-use behaviour unchanged and is
  # fail-safe (see `Attesto.CodeStore`). `meta` links the spent code to the
  # family it spawned so the caller can revoke descendants on a later replay.
  defp record_consumption(store, code_hash, %Grant{} = grant) do
    if function_exported?(store, :mark_consumed, 2) do
      case store.mark_consumed(code_hash, %{family_id: grant.family_id, subject: grant.subject}) do
        :ok -> :ok
        _unexpected -> code_store_contract_error(:mark_consumed)
      end
    end

    :ok
  end

  # RFC 6749 §4.1.3: the code must be redeemed by the client it was issued
  # to. Fail closed by default - a stored code always carries a
  # `client_id`, so redemption MUST present a matching one
  # (`:client_required` when absent, `:client_mismatch` when wrong). A
  # caller that genuinely cannot authenticate the client (and relies on
  # PKCE alone) opts out explicitly with `allow_missing_client_id?: true`.
  defp check_client(%{client_id: stored}, params, opts) do
    case Map.get(params, :client_id) do
      nil -> if allow_missing_client?(opts), do: :ok, else: {:error, :client_required}
      ^stored -> :ok
      _ -> {:error, :client_mismatch}
    end
  end

  defp allow_missing_client?(opts) do
    case Keyword.fetch(opts, :allow_missing_client_id?) do
      :error -> false
      {:ok, value} when is_boolean(value) -> value
      {:ok, _value} -> raise ArgumentError, ":allow_missing_client_id? must be true or false"
    end
  end

  # ----- issue validation -----

  defp validate_method(attrs) do
    case {Map.get(attrs, :code_challenge), Map.get(attrs, :code_challenge_method)} do
      {nil, nil} -> :ok
      {nil, _method} -> {:error, :unsupported_code_challenge_method}
      {_challenge, nil} -> :ok
      {_challenge, "S256"} -> :ok
      {_challenge, _method} -> {:error, :unsupported_code_challenge_method}
    end
  end

  defp normalize_issue_attrs(attrs) do
    scope = Map.get(attrs, :scope, [])
    resource = Map.get(attrs, :resource, [])
    dpop_jkt = Map.get(attrs, :dpop_jkt)
    family_id = Map.get(attrs, :family_id)
    claims = Map.get(attrs, :claims, %{})

    with :ok <- validate_issue_attrs(attrs, scope, resource, dpop_jkt, family_id, claims) do
      {:ok,
       %{
         client_id: attrs.client_id,
         redirect_uri: attrs.redirect_uri,
         code_challenge: Map.get(attrs, :code_challenge),
         subject: attrs.subject,
         scope: scope,
         resource: resource,
         dpop_jkt: dpop_jkt,
         family_id: family_id,
         claims: claims
       }}
    end
  end

  # Each issue attribute is checked in a fixed precedence order; the first
  # failure wins. Driving the checks from a list keeps the precedence
  # explicit while holding the function's branching low.
  defp validate_issue_attrs(attrs, scope, resource, dpop_jkt, family_id, claims) do
    [
      {non_empty_binary?(Map.get(attrs, :client_id)), :invalid_client_id},
      {non_empty_binary?(Map.get(attrs, :redirect_uri)), :invalid_redirect_uri},
      {valid_optional_challenge?(Map.get(attrs, :code_challenge)), :invalid_code_challenge},
      {non_empty_binary?(Map.get(attrs, :subject)), :invalid_subject},
      {valid_scope?(scope), :invalid_scope},
      # RFC 8707 §2.2: the resource indicator(s) the user authorized are bound to
      # the code (like scope) so the token endpoint mints `aud` from what was
      # granted at authorization, not a value re-submitted at redemption.
      {valid_resource?(resource), :invalid_resource},
      {valid_optional_jkt?(dpop_jkt), :invalid_dpop_jkt},
      {valid_optional_family_id?(family_id), :invalid_family_id},
      {is_map(claims), :invalid_claims}
    ]
    |> Enum.find_value(:ok, fn {ok?, error} -> if ok?, do: false, else: {:error, error} end)
  end

  # ----- redeem validation -----

  defp check_expiry(expires_at, opts) do
    if expires_at > NumericDate.now(opts), do: :ok, else: {:error, :expired}
  end

  # RFC 6749 §3.1.2 / §4.1.3: the redirect URI is compared by exact
  # string match, never normalised, to deny open-redirect smuggling.
  defp check_redirect_uri(%{redirect_uri: registered}, %{redirect_uri: presented}) do
    if is_binary(presented) and presented == registered,
      do: :ok,
      else: {:error, :redirect_uri_mismatch}
  end

  defp check_redirect_uri(_data, _params), do: {:error, :redirect_uri_mismatch}

  defp check_pkce(%{code_challenge: challenge}, %{code_verifier: verifier}) when is_binary(challenge) do
    case PKCE.verify(challenge, verifier) do
      :ok -> :ok
      # Collapse every PKCE failure to one error so a redemption cannot
      # distinguish "wrong verifier" from "malformed verifier".
      {:error, _} -> {:error, :pkce_failed}
    end
  end

  # A code issued without a challenge (the host relaxed PKCE for a confidential
  # client - see `Attesto.AuthorizationRequest`'s `:require_pkce`) is redeemed
  # without a verifier. Presenting a verifier against such a code is an anomaly
  # (the client behaves as if it used PKCE when the code is unbound), so it fails
  # closed; a challenge bound but no verifier presented likewise fails.
  defp check_pkce(%{code_challenge: nil}, params) do
    case Map.get(params, :code_verifier) do
      nil -> :ok
      _ -> {:error, :pkce_failed}
    end
  end

  defp check_pkce(_data, _params), do: {:error, :pkce_failed}

  # RFC 9449 §10 lets a client bind the authorization code itself with a
  # `dpop_jkt` authorization-request parameter. When that pre-binding exists,
  # redemption must present the exact same proof key. If the code was not
  # pre-bound, a DPoP proof at the token endpoint is still valid: it constrains
  # the access token being minted, not the already-issued code.
  defp check_dpop(%{dpop_jkt: bound}, params) when is_binary(bound) do
    case Map.get(params, :dpop_jkt) do
      # Only a wholly absent proof is "required"; any present-but-wrong
      # value (mismatched binary or malformed) is a binding mismatch.
      nil -> {:error, :dpop_proof_required}
      ^bound -> :ok
      _ -> {:error, :dpop_binding_mismatch}
    end
  end

  defp check_dpop(_data, _params), do: :ok

  # ----- helpers -----

  defp non_empty_binary?(v), do: is_binary(v) and v != ""

  defp valid_record?(
         %{
           code_hash: record_hash,
           data:
             %{
               client_id: client_id,
               redirect_uri: redirect_uri,
               code_challenge: code_challenge,
               subject: subject,
               scope: scope,
               resource: resource,
               dpop_jkt: dpop_jkt,
               family_id: family_id,
               claims: claims
             } = data,
           expires_at: expires_at
         },
         expected_hash
       ) do
    exact_canonical_data_keys?(data) and
      valid_code_identity?(record_hash, expected_hash, client_id, redirect_uri) and
      valid_code_grant?(code_challenge, subject, scope, resource) and
      valid_code_context?(dpop_jkt, family_id, claims, expires_at)
  end

  defp valid_record?(_record, _expected_hash), do: false

  defp valid_code_identity?(record_hash, expected_hash, client_id, redirect_uri) do
    record_hash == expected_hash and non_empty_binary?(client_id) and non_empty_binary?(redirect_uri)
  end

  defp valid_code_grant?(code_challenge, subject, scope, resource) do
    valid_optional_challenge?(code_challenge) and non_empty_binary?(subject) and
      valid_scope?(scope) and valid_resource?(resource)
  end

  defp valid_code_context?(dpop_jkt, family_id, claims, expires_at) do
    valid_optional_jkt?(dpop_jkt) and valid_optional_family_id?(family_id) and
      is_map(claims) and is_integer(expires_at)
  end

  # The authorization-code grant context is canonical. Host-specific values
  # belong inside `:claims`, so extra sibling keys make a persisted record
  # malformed rather than being silently ignored.
  defp exact_canonical_data_keys?(data),
    do: map_size(data) == length(@canonical_data_keys) and Enum.all?(@canonical_data_keys, &Map.has_key?(data, &1))

  defp code_store_contract_error(:put) do
    raise RuntimeError, "authorization code store put/1 violated its contract"
  end

  defp code_store_contract_error(:take) do
    raise RuntimeError, "authorization code store take/1 violated its contract"
  end

  defp code_store_contract_error(:get) do
    raise RuntimeError, "authorization code store get/1 violated its contract"
  end

  defp code_store_contract_error(:mark_consumed) do
    raise RuntimeError, "authorization code store mark_consumed/2 violated its contract"
  end

  # PKCE is optional at issuance: a host that relaxed `:require_pkce` for a
  # confidential client issues a code with no challenge (nil). A challenge that
  # IS present must be a valid S256 challenge (RFC 7636); nil is accepted, any
  # other value is rejected as `:invalid_code_challenge`.
  defp valid_optional_challenge?(nil), do: true
  defp valid_optional_challenge?(challenge), do: PKCE.valid_challenge?(challenge)
  defp valid_scope?(scope), do: Scope.valid_list?(scope)
  # The bound resource indicators are validated as RFC 8707 §2.1 absolute-URI
  # indicators at the authorization-server framing layer; here they are
  # shape-checked as a list of non-empty strings before being stored.
  defp valid_resource?(resource), do: is_list(resource) and Enum.all?(resource, &non_empty_binary?/1)
  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(jkt), do: Thumbprint.valid?(jkt)
  defp valid_optional_family_id?(nil), do: true
  defp valid_optional_family_id?(family_id), do: non_empty_binary?(family_id)
end
