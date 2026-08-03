defmodule Attesto.PresentationSession do
  @moduledoc """
  Verifier-side OID4VP presentation-session state machine.

  `create/3` persists the nonce, audience, requested DCQL IDs, and issuer trust
  needed to verify a later `direct_post` response. The opaque session `id` is
  also the OID4VP `state` value, so a wallet response can be correlated without
  a second index or identifier.

  Verification delegates all SD-JWT VC and holder-binding cryptography to
  `Attesto.VpToken.verify/2`. A malformed or invalid presentation leaves the
  session pending, allowing a valid response to arrive before expiry. Only a
  successfully verified response attempts the store's atomic completion.

  A `{:resolve_issuer, fun}` trust source contains an in-memory function and is
  therefore suitable only for in-memory stores such as the bundled ETS store.
  Persistent stores must use static `{:issuer_jwks, jwks}` trust material (or
  define their own serializable trust-reference convention outside this core
  primitive).
  """

  alias Attesto.{NumericDate, Secret, VpToken}

  @default_ttl_seconds 300

  @type issuer_trust :: {:issuer_jwks, map() | list()} | {:resolve_issuer, (String.t() -> term())}

  @type create_attrs :: %{
          required(:audience) => String.t(),
          required(:expected_query_ids) => [String.t()],
          required(:issuer_trust) => issuer_trust()
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

  @doc "Read a completed session's verified result without consuming it."
  @spec result(module(), String.t()) :: {:ok, map()} | :error
  def result(store, id) when is_atom(store) and is_binary(id) do
    now = NumericDate.now([])

    # Return the same shape as `verify_response/4` — the VpToken results map
    # directly — so a host polling `result/2` and a host reading the live
    # `verify_response/4` return value handle one shape, not two.
    case store.get(id) do
      {:ok, %{expires_at: expires_at, data: %{status: :completed, result: %{results: results}}}}
      when expires_at > now and is_map(results) ->
        {:ok, results}

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

    if non_empty_string?(audience) and valid_query_ids?(expected_query_ids) and
         valid_issuer_trust?(issuer_trust) and valid_request_object?(request_object) do
      {:ok,
       %{
         audience: audience,
         expected_query_ids: expected_query_ids,
         issuer_trust: issuer_trust
       }
       |> put_optional(:request_object, request_object)}
    else
      {:error, :invalid_attrs}
    end
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp valid_request_object?(nil), do: true
  defp valid_request_object?(value), do: non_empty_string?(value)

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
      |> Keyword.merge(Keyword.take(opts, [:now]))

    case VpToken.verify(vp_token, verify_opts) do
      {:ok, results} -> {:ok, results}
      {:error, reason} -> {:error, {:invalid_presentation, reason}}
    end
  end

  defp issuer_trust_opts({:issuer_jwks, jwks}), do: [issuer_jwks: jwks]
  defp issuer_trust_opts({:resolve_issuer, resolver}), do: [resolve_issuer: resolver]

  defp complete(store, id, results) do
    case store.complete(id, %{results: results}) do
      :ok -> :ok
      :error -> {:error, :already_completed}
    end
  end
end
