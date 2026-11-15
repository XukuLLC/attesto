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
  and redeemed without requiring a verifier. A `code_challenge` that is present is always
  fully enforced. `issue/3` therefore treats `:code_challenge` as optional: when
  given it must be a valid S256 challenge, when absent the code is unbound and a
  later redemption must omit the verifier to prevent PKCE downgrade.

  ## Compare before single use

  `redeem/4` reads via `c:Attesto.CodeStore.read/1`, checks client,
  redirect URI, PKCE and DPoP, then acts on the explicit state. A failed
  comparison returns its reason without writes in every state. A matching live
  code is checked for expiry and atomically claimed; a lost transition rereads
  and compares again, at most three times before a store contract violation.

  A matching claimed code flags replay for finalization. A matching redeemed
  code returns `{:error, {:reuse, meta}}` with the first redemption's family,
  subject and retention deadline. Expiry is checked only for live codes. An
  unchallenged code compares client and redirect URI and refuses a presented verifier.
  Every store retains bindings and redemption records; all callbacks are required.

  `finalize/3` and `issue_refresh_and_finalize/6` finish issuance atomically,
  observe concurrent replay or grant cut-off revocation, and revoke issued tokens
  when necessary. Stores themselves make no replay or revocation decisions.

  This deliberately departs from the literal wording of RFC 6749 §4.1.2:
  revocation requires a matching presentation so possession of a code alone
  cannot revoke another client's tokens.

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
  alias Attesto.Claims
  alias Attesto.NumericDate
  alias Attesto.Options
  alias Attesto.PKCE
  alias Attesto.Record
  alias Attesto.Scope
  alias Attesto.Secret
  alias Attesto.Store

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
          optional(:code_verifier) => String.t(),
          required(:client_id) => String.t(),
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
          | {:reuse, Attesto.CodeStore.redemption()}

  @doc """
  Mint a single-use authorization code and persist it via `store`.

  `attrs` MUST carry `:client_id`, `:redirect_uri`, and `:subject`.
  Optional `:code_challenge` binds the code to PKCE; when present,
  `:code_challenge_method` must be `"S256"` if given. Optional `:scope` (a
  list of strings, default `[]`), `:dpop_jkt` (binds the code to a DPoP key),
  `:family_id` (a non-empty provenance string round-tripped to the redeemed
  `Grant`; use `issue_refresh_and_finalize/6` to bind the actually issued
  refresh family), and
  `:claims` (a lossless, string-keyed I-JSON object of host context;
  persisted numbers are exact-range integers, not floats) round-tripped to
  `redeem/4`.

  Options: `:ttl` (seconds the code is valid, default
  #{@default_ttl_seconds}) and `:now` (clock override).

  Returns `{:ok, code}` with the plaintext code to hand the client. Only
  the code's hash is stored. Returns `{:error, reason}` on malformed
  `attrs`.
  """
  @spec issue(module(), issue_attrs(), keyword()) :: {:ok, String.t()} | {:error, issue_error()}
  def issue(store, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    Attesto.CodeStore.validate!(store)

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

  defp ttl_seconds!(opts), do: Options.positive_integer!(opts, :ttl, @default_ttl_seconds)

  @doc """
  Validate and consume a code at the token endpoint.

  `params` MUST carry the `:redirect_uri` (matched exactly against the one
  in the authorization request), the `:code_verifier` (checked against the
  stored PKCE challenge), and the `:client_id` of the redeeming client. By
  default client binding is fail-closed: since every stored code carries a
  `client_id`, redemption MUST present one (`:client_required` if absent,
  `:client_mismatch` if wrong) - this stops a code issued to one client
  being redeemed by another (RFC 6749 §4.1.3). `:dpop_jkt` is required iff
  the code was DPoP-bound at `issue/3`; if the code was not bound, a presented
  `:dpop_jkt` is allowed and can be used by the caller to mint a DPoP-bound
  access token.

  The code is read and validated before its atomic claim. Returns
  `{:ok, %Attesto.AuthorizationCode.Grant{}}` with the validated grant
  context, or `{:error, reason}`.

  A second redemption of a code that was already
  successfully redeemed and whose bindings match returns `{:error, {:reuse, meta}}` rather than
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

    if Keyword.has_key?(opts, :allow_missing_client_id?) do
      raise ArgumentError, ":allow_missing_client_id? is no longer supported for authorization codes"
    end

    opts = Keyword.put(opts, :now, now)
    code_hash = Secret.hash(code)

    Attesto.CodeStore.validate!(store)
    redeem_read(store, code_hash, params, opts, 3)
  end

  defp redeem_read(_store, _hash, _params, _opts, -1), do: code_store_contract_error(:read)

  defp redeem_read(store, code_hash, params, opts, rereads) do
    case store.read(code_hash) do
      {:ok, record} ->
        if !valid_state_record?(record, code_hash), do: code_store_contract_error(:read)

        with {:ok, grant} <- compare_record(record, params, opts) do
          act_on_state(store, record, grant, params, opts, rereads)
        end

      :error ->
        {:error, :invalid_grant}

      _unexpected ->
        code_store_contract_error(:read)
    end
  end

  defp act_on_state(store, %{state: :live, code_hash: hash, expires_at: expiry}, grant, params, opts, rereads) do
    with :ok <- check_expiry(expiry, opts) do
      case store.claim(hash) do
        :ok -> {:ok, grant}
        :error -> redeem_read(store, hash, params, opts, rereads - 1)
        _unexpected -> code_store_contract_error(:claim)
      end
    end
  end

  defp act_on_state(store, %{state: :claimed, code_hash: hash}, _grant, params, opts, rereads) do
    case store.flag_replay(hash) do
      :ok -> {:error, :invalid_grant}
      :error -> redeem_read(store, hash, params, opts, rereads - 1)
      _unexpected -> code_store_contract_error(:flag_replay)
    end
  end

  defp act_on_state(_store, %{state: :redeemed, redemption: redemption}, _grant, _params, _opts, _rereads),
    do: {:error, {:reuse, redemption}}

  defp valid_state_record?(%{state: state, redemption: redemption, revoked: revoked} = record, hash) do
    valid_record?(record, hash) and is_boolean(revoked) and
      valid_state_fields?(state, redemption, revoked)
  end

  defp valid_state_record?(_record, _hash), do: false

  defp valid_state_fields?(:live, nil, false), do: true
  defp valid_state_fields?(:claimed, nil, _revoked), do: true
  defp valid_state_fields?(:redeemed, redemption, _revoked), do: valid_redemption?(redemption)
  defp valid_state_fields?(_state, _redemption, _revoked), do: false

  defp valid_redemption?(%{family_id: family, subject: subject, replay_retain_until: deadline}) do
    valid_optional_family_id?(family) and Record.non_empty_binary?(subject) and
      (is_nil(deadline) or (is_integer(deadline) and deadline >= 0))
  end

  defp valid_redemption?(_redemption), do: false

  @doc """
  Returns `true` iff a stored code for `code` is bound to a DPoP key (RFC 9449
  §10) - i.e. its redemption requires a matching DPoP proof (holder-of-key).

  Reads the code via the store's required `c:Attesto.CodeStore.read/1` WITHOUT
  consuming it, so a legitimate redemption is unaffected. Returns `false` when
  the code is unknown, already consumed, or carries no `:dpop_jkt`. Missing `read/1` is a
  store contract violation.
  This lets the token endpoint surface a holder-of-key (`invalid_dpop_proof`)
  rejection ahead of the client-authentication error (FAPI2) without burning the
  single-use code.
  """
  @spec dpop_bound?(module(), String.t()) :: boolean()
  def dpop_bound?(store, code) when is_atom(store) and is_binary(code) do
    Attesto.CodeStore.validate!(store)
    hash = Secret.hash(code)

    case store.read(hash) do
      {:ok, record} ->
        if !valid_state_record?(record, hash), do: code_store_contract_error(:read)
        record.state == :live and not is_nil(record.data.dpop_jkt)

      :error ->
        false

      _unexpected ->
        code_store_contract_error(:read)
    end
  end

  defp compare_record(%{data: data}, params, opts) do
    with :ok <- check_client(data, params, opts),
         :ok <- check_redirect_uri(data, params),
         :ok <- check_pkce(data, params),
         :ok <- check_dpop(data, params) do
      {:ok, Grant.from_data(data)}
    end
  end

  @doc """
  Finalize a fully completed redemption: record the reuse marker
  for `code`'s grant.

  Call this only AFTER the full token response has been successfully built. It
  is split from `redeem/4` so redemption is atomic - `redeem/4` claims the code
  (single use, via `c:Attesto.CodeStore.claim/1`) after validating it, but defers this marker so a
  failure in the caller's downstream issuance (mint, refresh-token persistence,
  a host callback fault) does NOT leave a spent-but-tokenless code recorded as a
  completed redemption (which would make a legitimate retry look like a reuse
  attack and revoke the family). This form is only for flows that issue
  no refresh token and always records a nil `family_id` in the marker. The
  `Grant`'s `family_id` is authorization provenance, not a refresh-family
  identifier. For a refresh grant, use `issue_refresh_and_finalize/6` so the
  marker carries the family ID returned by `RefreshToken.issue/3` without
  accepting a caller-supplied ID. A missing claim returns `{:error, :invalid_grant}`
  after revoking its access-token link.
  """
  @spec finalize(module(), String.t(), Grant.t()) :: :ok | {:error, :invalid_grant}
  def finalize(store, code, %Grant{} = grant) when is_atom(store) and is_binary(code) do
    # An authorization-request family is provenance only. A no-refresh marker
    # must never be mistaken for the family of a refresh credential.
    case finish_redemption(store, Secret.hash(code), %{grant | family_id: nil}) do
      :error -> {:error, :invalid_grant}
      {:ok, _revoked} -> :ok
    end
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
  reach `c:Attesto.CodeStore.finish/2`, and the exact family ID captured from that result is
  written to the code-reuse marker. A refresh issuance error is returned
  unchanged and leaves the code spent-but-unfinalized. If the claim disappears,
  the newly issued refresh family and access-token link are revoked and
  `{:error, :invalid_grant}` is returned. A finalization exception
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
        ) :: {:ok, Attesto.RefreshToken.issued()} | {:error, Attesto.RefreshToken.issue_error() | :invalid_grant}
  def issue_refresh_and_finalize(code_store, code, %Grant{} = grant, refresh_store, refresh_context, opts \\ [])
      when is_atom(code_store) and is_binary(code) and is_atom(refresh_store) and is_map(refresh_context) and
             is_list(opts) do
    validate_refresh_context!(grant, refresh_context)

    # Freeze the issuance clock once so the refresh family's persisted deadline
    # and the authorization-code reuse marker use the same instant. Without an
    # explicit clock, separate calls around a one-second boundary could make the
    # marker expire before the family it protects.
    opts = Keyword.put_new_lazy(opts, :now, fn -> NumericDate.now([]) end)

    code_hash = Secret.hash(code)

    case Attesto.RefreshToken.issue(refresh_store, refresh_context, opts) do
      {:ok, issued} ->
        issued = validate_issued_refresh!(issued)

        revoked =
          finish_redemption(
            code_store,
            code_hash,
            %{grant | family_id: issued.family_id},
            refresh_family_deadline(opts)
          )

        finish_refresh_result(revoked, refresh_store, issued)

      {:error, _reason} = error ->
        error
    end
  end

  defp finish_refresh_result(:error, refresh_store, issued) do
    revoke_issued_family!(refresh_store, issued.family_id)
    {:error, :invalid_grant}
  end

  defp finish_refresh_result({:ok, revoked?}, refresh_store, issued) do
    if revoked?, do: revoke_issued_family!(refresh_store, issued.family_id)
    {:ok, issued}
  end

  defp revoke_issued_family!(refresh_store, family_id) do
    case refresh_store.revoke_family(family_id) do
      :ok -> :ok
      _unexpected -> Store.contract_violation!("refresh store", {:revoke_family, 1})
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
    Record.non_empty_binary?(grant.client_id) and Record.non_empty_binary?(grant.redirect_uri) and
      Record.non_empty_binary?(grant.subject) and valid_scope?(grant.scope) and
      valid_resource?(grant.resource) and Record.optional_jkt?(grant.dpop_jkt) and
      valid_optional_family_id?(grant.family_id) and Claims.portable_json_object?(grant.claims)
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
    Store.contract_violation!("refresh token", {:issue, 3})
  end

  defp finish_redemption(store, code_hash, %Grant{} = grant, replay_retain_until \\ nil) do
    Attesto.CodeStore.validate!(store)
    redemption = %{family_id: grant.family_id, subject: grant.subject, replay_retain_until: replay_retain_until}

    case store.finish(code_hash, redemption) do
      {:ok, revoked} when is_boolean(revoked) ->
        if revoked, do: revoke_code_access_token!(store, code_hash)
        {:ok, revoked}

      :error ->
        revoke_code_access_token!(store, code_hash)
        :error

      _unexpected ->
        code_store_contract_error(:finish)
    end
  end

  defp revoke_code_access_token!(store, code_hash) do
    case store.revoke_access_token_for_code(code_hash) do
      :ok -> :ok
      _unexpected -> code_store_contract_error(:revoke_access_token_for_code)
    end
  end

  defp refresh_family_deadline(opts) do
    case Keyword.get(opts, :family_ttl) do
      nil -> nil
      ttl when is_integer(ttl) and ttl > 0 -> NumericDate.now(opts) + ttl
      # RefreshToken.issue/3 validates this option before a success can reach
      # here. Keep a fail-closed guard in case that contract ever changes.
      _invalid -> raise RuntimeError, "refresh token issue/3 accepted an invalid family lifetime"
    end
  end

  defp check_client(%{client_id: stored}, params, _opts) do
    case Map.get(params, :client_id) do
      nil -> {:error, :client_required}
      ^stored -> :ok
      _ -> {:error, :client_mismatch}
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
      {Record.non_empty_binary?(Map.get(attrs, :client_id)), :invalid_client_id},
      {Record.non_empty_binary?(Map.get(attrs, :redirect_uri)), :invalid_redirect_uri},
      {valid_optional_challenge?(Map.get(attrs, :code_challenge)), :invalid_code_challenge},
      {Record.non_empty_binary?(Map.get(attrs, :subject)), :invalid_subject},
      {valid_scope?(scope), :invalid_scope},
      # RFC 8707 §2.2: the resource indicator(s) the user authorized are bound to
      # the code (like scope) so the token endpoint mints `aud` from what was
      # granted at authorization, not a value re-submitted at redemption.
      {valid_resource?(resource), :invalid_resource},
      {Record.optional_jkt?(dpop_jkt), :invalid_dpop_jkt},
      {valid_optional_family_id?(family_id), :invalid_family_id},
      {Claims.portable_json_object?(claims), :invalid_claims}
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
    Record.exact_keys?(data, @canonical_data_keys) and
      valid_code_identity?(record_hash, expected_hash, client_id, redirect_uri) and
      valid_code_grant?(code_challenge, subject, scope, resource) and
      valid_code_context?(dpop_jkt, family_id, claims, expires_at)
  end

  defp valid_record?(_record, _expected_hash), do: false

  defp valid_code_identity?(record_hash, expected_hash, client_id, redirect_uri) do
    record_hash == expected_hash and Record.non_empty_binary?(client_id) and Record.non_empty_binary?(redirect_uri)
  end

  defp valid_code_grant?(code_challenge, subject, scope, resource) do
    valid_optional_challenge?(code_challenge) and Record.non_empty_binary?(subject) and
      valid_scope?(scope) and valid_resource?(resource)
  end

  defp valid_code_context?(dpop_jkt, family_id, claims, expires_at) do
    Record.optional_jkt?(dpop_jkt) and valid_optional_family_id?(family_id) and
      Claims.portable_json_object?(claims) and is_integer(expires_at)
  end

  # The authorization-code grant context is canonical. Host-specific values
  # belong inside `:claims`, so extra sibling keys make a persisted record
  # malformed rather than being silently ignored.
  @spec code_store_contract_error(atom()) :: no_return()
  defp code_store_contract_error(:finish), do: Store.contract_violation!("authorization code store", {:finish, 2})
  defp code_store_contract_error(callback), do: Store.contract_violation!("authorization code store", {callback, 1})
  defp valid_optional_challenge?(nil), do: true
  defp valid_optional_challenge?(challenge), do: PKCE.valid_challenge?(challenge)
  defp valid_scope?(scope), do: Scope.valid_list?(scope)
  defp valid_resource?(resource), do: is_list(resource) and Enum.all?(resource, &Record.non_empty_binary?/1)
  defp valid_optional_family_id?(family_id), do: Record.optional_non_empty_binary?(family_id)
end
