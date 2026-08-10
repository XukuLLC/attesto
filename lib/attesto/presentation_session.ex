defmodule Attesto.PresentationSession do
  @moduledoc """
  Verifier-side OID4VP presentation-session state machine.

  `create/3` persists the nonce, audience, requested DCQL IDs, and issuer trust
  needed to verify a later `direct_post` response. The opaque session `id` is
  also the OID4VP `state` value, so a wallet response can be correlated without
  a second index or identifier. An optional `:response_uri` attr is also
  stored and forwarded to `Attesto.VpToken.verify/2`; it is required only if
  the session expects an `mso_mdoc` presentation (see `Attesto.VpToken`'s
  moduledoc) and may be omitted for SD-JWT-VC-only sessions exactly as before.

  Verification delegates all SD-JWT VC / mdoc and holder-binding cryptography
  to `Attesto.VpToken.verify/2`. A malformed or invalid presentation leaves the
  session pending, allowing a valid response to arrive before expiry. Only a
  successfully verified response attempts the store's atomic completion.

  A `{:resolve_issuer, fun}` trust source contains an in-memory function and is
  therefore suitable only for in-memory stores such as the bundled ETS store.
  Persistent stores must use static `{:issuer_jwks, jwks}` trust material (or
  define their own serializable trust-reference convention outside this core
  primitive).
  """

  alias Attesto.{MapParams, NumericDate, Secret, VpToken}

  @default_ttl_seconds 300

  @type issuer_trust :: {:issuer_jwks, map() | list()} | {:resolve_issuer, (String.t() -> term())}

  @type create_attrs :: %{
          required(:audience) => String.t(),
          required(:expected_query_ids) => [String.t()],
          required(:issuer_trust) => issuer_trust(),
          optional(:request_object) => String.t(),
          optional(:response_uri) => String.t()
        }

  @type correlation :: {:state, String.t()} | {:id, String.t()}

  @doc """
  Create and persist a short-lived OID4VP presentation session.

  The returned `id` is both the store key and the request's `state`; `nonce`
  belongs in the presentation request. Options are `:ttl` (default
  `#{@default_ttl_seconds}` seconds) and `:now` (a clock override).
  """
  @spec create(module(), create_attrs(), keyword()) ::
          {:ok, %{id: String.t(), nonce: String.t()}} | {:error, :invalid_attrs}
  def create(store, attrs, opts \\ []) when is_atom(store) and is_map(attrs) and is_list(opts) do
    with {:ok, data} <- normalize_attrs(attrs) do
      id = Secret.generate()
      nonce = Secret.generate()
      ttl = Keyword.get(opts, :ttl, @default_ttl_seconds)

      :ok =
        store.put(%{
          id: id,
          data:
            data
            |> Map.put(:nonce, nonce)
            |> Map.put(:state, id)
            |> Map.put(:status, :pending),
          expires_at: NumericDate.now(opts) + ttl
        })

      {:ok, %{id: id, nonce: nonce}}
    end
  end

  @doc """
  Verify a wallet response and atomically complete its pending session.

  Invalid presentations return `{:invalid_presentation, reason}` and do not
  complete the session. When concurrent valid responses race, exactly one can
  complete it; all losing calls return `:already_completed`.
  """
  @spec verify_response(module(), correlation(), map(), keyword()) ::
          {:ok, map()}
          | {:error, :unknown_session | :expired | :already_completed | {:invalid_presentation, term()}}
  def verify_response(store, correlation, vp_token, opts \\ []) when is_atom(store) and is_list(opts) do
    with {:ok, id} <- correlation_id(correlation),
         {:ok, entry} <- load_pending(store, id, opts),
         {:ok, results} <- verify(vp_token, entry.data, opts),
         :ok <- complete(store, id, results) do
      {:ok, results}
    end
  end

  @doc """
  Read and consume a completed session's verified result. Single-use.

  The result is returned at most once: the completed session is atomically
  removed on read (via the store's `take/1`). This bounds exposure of the
  presented — potentially PII — claims. The `response_code` a verifier hands the
  browser to trigger this read is the session id, and it transits the browser
  address bar, history, `Referer`, and logs; a non-consuming read would let
  anyone who later captured that value replay it to re-read the claims for the
  rest of the session TTL. Single-use closes that: the verifier front-end reads
  the result once, on the completion redirect, and a captured `response_code` is
  dead afterwards. A second read (or a read of a still-pending/expired session)
  returns `:error`.

  Returns the same shape as `verify_response/4` — the VpToken results map
  directly — so the live-return and read-back paths handle one shape, not two.
  """
  @spec result(module(), String.t()) :: {:ok, map()} | :error
  def result(store, id) when is_atom(store) and is_binary(id) do
    case store.take(id) do
      {:ok, %{data: %{status: :completed, result: %{results: results}}}} when is_map(results) ->
        {:ok, results}

      _other ->
        :error
    end
  end

  @doc """
  Attach the signed OID4VP request object to a pending session.

  Called once at creation time (the request object needs the session's `nonce`
  and its `id`/`state`, which `create/3` generates). Atomic on the pending
  status. Returns `{:error, :unavailable}` if the session is unknown, expired,
  or already completed.
  """
  @spec attach_request_object(module(), String.t(), String.t()) :: :ok | {:error, :unavailable}
  def attach_request_object(store, id, request_object)
      when is_atom(store) and is_binary(id) and is_binary(request_object) and request_object != "" do
    case store.attach_request_object(id, request_object) do
      :ok -> :ok
      :error -> {:error, :unavailable}
    end
  end

  @doc """
  Attach the verifier's per-request response-encryption private JWK to a pending
  session (its `kid` is the session id), so the direct-post endpoint can decrypt
  a `direct_post.jwt` response with the ephemeral key it advertised.
  """
  @spec attach_response_encryption_jwk(module(), String.t(), map()) :: :ok | {:error, :unavailable}
  def attach_response_encryption_jwk(store, id, jwk) when is_atom(store) and is_binary(id) and is_map(jwk) do
    case store.attach_response_encryption_jwk(id, jwk) do
      :ok -> :ok
      :error -> {:error, :unavailable}
    end
  end

  @doc """
  Read a pending session's per-request response-encryption private JWK, if one
  was attached. Returns `:error` for an unknown, expired, or key-less session.
  """
  @spec response_encryption_jwk(module(), String.t()) :: {:ok, map()} | :error
  def response_encryption_jwk(store, id) when is_atom(store) and is_binary(id) do
    now = NumericDate.now([])

    case store.get(id) do
      {:ok, %{expires_at: expires_at, data: %{response_encryption_jwk: jwk}}}
      when expires_at > now and is_map(jwk) ->
        {:ok, jwk}

      _other ->
        :error
    end
  end

  @doc """
  Read a pending session's stored request object (the signed OID4VP request
  object the interface serves at its `request_uri`), if one was persisted at
  `create/3` via the optional `:request_object` attr. Returns `:error` for an
  unknown, expired, or request-object-less session.
  """
  @spec request_object(module(), String.t()) :: {:ok, String.t()} | :error
  def request_object(store, id) when is_atom(store) and is_binary(id) do
    now = NumericDate.now([])

    case store.get(id) do
      {:ok, %{expires_at: expires_at, data: %{request_object: request_object}}}
      when expires_at > now and is_binary(request_object) ->
        {:ok, request_object}

      _other ->
        :error
    end
  end

  defp normalize_attrs(attrs) do
    audience = Map.get(attrs, :audience)
    expected_query_ids = Map.get(attrs, :expected_query_ids)
    issuer_trust = Map.get(attrs, :issuer_trust)
    request_object = Map.get(attrs, :request_object)
    response_uri = Map.get(attrs, :response_uri)

    if non_empty_string?(audience) and valid_query_ids?(expected_query_ids) and
         valid_issuer_trust?(issuer_trust) and valid_request_object?(request_object) and
         valid_response_uri?(response_uri) do
      {:ok,
       %{
         audience: audience,
         expected_query_ids: expected_query_ids,
         issuer_trust: issuer_trust
       }
       |> MapParams.put_optional(:request_object, request_object)
       |> MapParams.put_optional(:response_uri, response_uri)}
    else
      {:error, :invalid_attrs}
    end
  end

  defp valid_request_object?(nil), do: true
  defp valid_request_object?(value), do: non_empty_string?(value)

  defp valid_response_uri?(nil), do: true
  defp valid_response_uri?(value), do: non_empty_string?(value)

  defp valid_query_ids?(ids) when is_list(ids), do: Enum.all?(ids, &non_empty_string?/1)
  defp valid_query_ids?(_ids), do: false

  defp valid_issuer_trust?({:issuer_jwks, jwks}), do: is_map(jwks) or is_list(jwks)
  defp valid_issuer_trust?({:resolve_issuer, resolver}), do: is_function(resolver, 1)
  defp valid_issuer_trust?(_issuer_trust), do: false

  defp non_empty_string?(value), do: is_binary(value) and value != ""

  defp correlation_id({kind, id}) when kind in [:state, :id] and is_binary(id) and id != "", do: {:ok, id}
  defp correlation_id(_correlation), do: {:error, :unknown_session}

  defp load_pending(store, id, opts) do
    now = NumericDate.now(opts)

    case store.get(id) do
      {:ok, %{expires_at: expires_at}} when expires_at <= now ->
        {:error, :expired}

      {:ok, %{data: %{status: :pending}} = entry} ->
        {:ok, entry}

      {:ok, _entry} ->
        {:error, :already_completed}

      :error ->
        {:error, :unknown_session}
    end
  end

  defp verify(vp_token, data, opts) do
    verify_opts =
      [
        nonce: data.nonce,
        audience: data.audience,
        expected_query_ids: data.expected_query_ids
      ]
      |> Keyword.merge(issuer_trust_opts(data.issuer_trust))
      |> Keyword.merge(response_uri_opts(data))
      |> Keyword.merge(response_encryption_jwk_opts(data))
      |> Keyword.merge(Keyword.take(opts, [:now, :formats]))

    case VpToken.verify(vp_token, verify_opts) do
      {:ok, results} -> {:ok, results}
      {:error, reason} -> {:error, {:invalid_presentation, reason}}
    end
  end

  defp issuer_trust_opts({:issuer_jwks, jwks}), do: [issuer_jwks: jwks]
  defp issuer_trust_opts({:resolve_issuer, resolver}), do: [resolve_issuer: resolver]

  defp response_uri_opts(%{response_uri: response_uri}), do: [response_uri: response_uri]
  defp response_uri_opts(_data), do: []

  # For an mdoc presentation over `direct_post.jwt`, the OpenID4VPHandover binds
  # to the verifier's response-encryption public key thumbprint; pass the key so
  # `Attesto.VpToken`/`Attesto.Mdoc` reconstruct the same SessionTranscript.
  defp response_encryption_jwk_opts(%{response_encryption_jwk: jwk}) when is_map(jwk),
    do: [response_encryption_jwk: jwk]

  defp response_encryption_jwk_opts(_data), do: []

  defp complete(store, id, results) do
    case store.complete(id, %{results: results}) do
      :ok -> :ok
      :error -> {:error, :already_completed}
    end
  end
end
