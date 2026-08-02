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
  `finalize/3`, which the caller invokes AFTER the full token response has been
  successfully built - NOT by `redeem/4` itself. So a code whose redemption
  validated but whose downstream issuance then failed (a mint or refresh-token
  fault, a host callback returning a bad principal) is left single-use-spent
  but NOT reuse-flagged: a replay is `{:error, :invalid_grant}`, and a
  legitimate retry of a transient failure is never mistaken for a reuse attack
  (which would wrongly revoke the family). Once `finalize/3` has run, a later
  redemption of the same code yields `{:error, {:reuse, meta}}`, where `meta`
  carries that first redemption's context so the caller can revoke the
  descendant family (e.g. via `Attesto.Revocation`). A store that does not
  implement the pair behaves exactly as before: a re-presented code is
  `{:error, :invalid_grant}`.
  This is additive and fail-safe (see `Attesto.CodeStore`).

  Pass a `:family_id` to `issue/3` to link the code to the refresh-token
  family it will spawn; it rides onto the returned `Grant` so the host
  mints the family under that id, and it is what reuse detection replays.

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
  alias Attesto.PKCE
  alias Attesto.Scope
  alias Attesto.Secret
  alias Attesto.Thumbprint

  @default_ttl_seconds 60

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
  `:family_id` (a
  non-empty string linking this code to the refresh-token family it will
  spawn; rides onto the redeemed `Grant` and is what code-reuse detection
  replays - see the moduledoc), and `:claims` (an opaque host context map
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
      code = Secret.generate()
      ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)

      :ok =
        store.put(%{
          code_hash: Secret.hash(code),
          data: data,
          expires_at: unix_now(opts) + ttl
        })

      {:ok, code}
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
  `:family_id` and `:subject` so the caller can revoke the descendant
  family (OAuth 2.0 Security BCP §4.13). Codes the store has never seen
  remain `{:error, :invalid_grant}`.
  """
  @spec redeem(module(), String.t(), redeem_params(), keyword()) ::
          {:ok, Grant.t()} | {:error, redeem_error()}
  def redeem(store, code, params, opts \\ []) when is_atom(store) and is_binary(code) and is_map(params) do
    case store.take(Secret.hash(code)) do
      {:ok, record} ->
        redeem_taken(record, params, opts)

      # OAuth 2.0 Security BCP §4.13 / RFC 6749 §4.1.2: a re-presented,
      # already-FINALIZED code is the reuse attack signal. Only stores with
      # reuse tracking return this, and only once `finalize/3` has recorded the
      # marker; surface the first redemption's context so the caller can revoke
      # the descendant family.
      {:error, :consumed, meta} ->
        {:error, {:reuse, meta}}

      :error ->
        {:error, :invalid_grant}
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
      case store.get(Secret.hash(code)) do
        {:ok, %{data: %{dpop_jkt: jkt}}} when is_binary(jkt) and jkt != "" -> true
        _ -> false
      end
    else
      false
    end
  end

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
  `c:Attesto.CodeStore.mark_consumed/2`.
  """
  @spec finalize(module(), String.t(), Grant.t()) :: :ok
  def finalize(store, code, %Grant{} = grant) when is_atom(store) and is_binary(code) do
    record_consumption(store, Secret.hash(code), grant)
  end

  # Record the successful redemption so a re-presentation of the same code
  # is detectable as reuse (OAuth 2.0 Security BCP §4.13). Only stores that
  # implement the optional `mark_consumed/2` callback get the marker; the
  # absence of the callback leaves single-use behaviour unchanged and is
  # fail-safe (see `Attesto.CodeStore`). `meta` links the spent code to the
  # family it spawned so the caller can revoke descendants on a later replay.
  defp record_consumption(store, code_hash, %Grant{} = grant) do
    if function_exported?(store, :mark_consumed, 2) do
      :ok = store.mark_consumed(code_hash, %{family_id: grant.family_id, subject: grant.subject})
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

  defp allow_missing_client?(opts), do: Keyword.get(opts, :allow_missing_client_id?, false)

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
    if expires_at > unix_now(opts), do: :ok, else: {:error, :expired}
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

  # PKCE is optional at issuance: a host that relaxed `:require_pkce` for a
  # confidential client issues a code with no challenge (nil). A challenge that
  # IS present must be a valid S256 challenge (RFC 7636); nil is accepted, any
  # other value is rejected as `:invalid_code_challenge`.
  defp valid_optional_challenge?(nil), do: true
  defp valid_optional_challenge?(challenge), do: PKCE.valid_challenge?(challenge)
  defp valid_scope?(scope), do: is_list(scope) and Enum.all?(scope, &Scope.valid_token?/1)
  # The bound resource indicators are validated as RFC 8707 §2.1 absolute-URI
  # indicators at the authorization-server framing layer; here they are
  # shape-checked as a list of non-empty strings before being stored.
  defp valid_resource?(resource), do: is_list(resource) and Enum.all?(resource, &non_empty_binary?/1)
  defp valid_optional_jkt?(nil), do: true
  defp valid_optional_jkt?(jkt), do: Thumbprint.valid?(jkt)
  defp valid_optional_family_id?(nil), do: true
  defp valid_optional_family_id?(family_id), do: non_empty_binary?(family_id)

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end
end
