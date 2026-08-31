defmodule Attesto.Revocation do
  @moduledoc """
  RFC 7009 - OAuth 2.0 Token Revocation, for refresh tokens.

  Revoking a refresh token revokes its entire family (every token
  descended from the same authorization), the same machinery refresh
  rotation uses for reuse detection. This module is the deliberate
  revocation entry point; it runs over an `Attesto.RefreshStore`.

  ## No-existence oracle (RFC 7009 §2.2)

  An invalid, expired, or unknown token does **not** produce an error:
  `revoke/3` returns `:ok` regardless of whether the token existed. A
  revocation endpoint must not let a caller probe which tokens are live,
  so revoking a token the store has never seen is indistinguishable from
  revoking a real one.

  ## Client binding (RFC 7009 §2.1)

  When the token carries a `client_id`, revocation is fail-closed: the
  caller MUST present a matching `:client_id` or the call returns
  `{:error, :unauthorized_client}`, so one client cannot revoke another
  client's tokens. A caller that cannot authenticate the client passes
  `allow_missing_client_id?: true`. A token issued without a client
  binding skips the check.

  ## Access tokens

  Attesto access tokens are stateless, short-lived JWTs, so there is no
  per-token revocation list to consult; revoking them is a host concern
  (rely on their short TTL, or maintain a `jti` denylist the resource
  server checks). This module revokes the stateful, family-backed refresh
  credential, which is what RFC 7009 revocation is primarily for.
  """

  alias Attesto.Secret

  @type revoke_error :: :unauthorized_client

  @doc """
  Revoke the refresh token `token` (and its whole family) via `store`.

  Returns `:ok` whether or not the token existed (no-existence oracle).
  Returns `{:error, :unauthorized_client}` only when the token carries a
  `client_id` and the presented `:client_id` does not match (or is absent
  without `allow_missing_client_id?: true`).

  Options: `:client_id` (the authenticated revoking client) and
  `:allow_missing_client_id?`.
  """
  @spec revoke(module(), String.t(), keyword()) :: :ok | {:error, revoke_error()}
  def revoke(store, token, opts \\ []) when is_atom(store) and is_binary(token) and is_list(opts) do
    _allow_missing_client = allow_missing_client?(opts)
    token_hash = Secret.hash(token)

    case store.get(token_hash) do
      {:ok, record} ->
        if valid_record?(record, token_hash),
          do: revoke_present(store, record, opts),
          else: store_contract_error(:get)

      :error ->
        # RFC 7009 §2.2: an invalid token is not an error.
        :ok

      _unexpected ->
        store_contract_error(:get)
    end
  end

  # An expired record remains a valid handle for revoking a family whose later
  # successor may still be live. Preserve the no-existence oracle for an
  # unauthorized caller: a wrong/missing client still receives `:ok`, but does
  # not revoke. A matching (or explicitly allowed missing) client revokes the
  # family and receives that same indistinguishable `:ok` response.
  defp revoke_present(store, record, opts) do
    if expired?(record) do
      case check_client(record.data, opts) do
        :ok -> revoke_family(store, record.family_id)
        {:error, :unauthorized_client} -> :ok
      end
    else
      with :ok <- check_client(record.data, opts) do
        revoke_family(store, record.family_id)
      end
    end
  end

  defp revoke_family(store, family_id) do
    case store.revoke_family(family_id) do
      :ok -> :ok
      _unexpected -> store_contract_error(:revoke_family)
    end
  end

  defp expired?(%{expires_at: expires_at}) when is_integer(expires_at) do
    expires_at <= System.system_time(:second)
  end

  defp expired?(_record), do: false

  defp valid_record?(
         %{token_hash: token_hash, family_id: family_id, data: data, expires_at: expires_at, consumed: consumed},
         expected_hash
       ) do
    token_hash == expected_hash and is_binary(family_id) and family_id != "" and
      is_map(data) and is_integer(expires_at) and is_boolean(consumed) and
      valid_client_binding?(data)
  end

  defp valid_record?(_record, _expected_hash), do: false

  defp valid_client_binding?(data) do
    case Map.fetch(data, :client_id) do
      :error -> true
      {:ok, nil} -> true
      {:ok, client_id} -> is_binary(client_id) and client_id != ""
    end
  end

  defp check_client(%{client_id: stored}, opts) when is_binary(stored) do
    case Keyword.get(opts, :client_id) do
      nil ->
        if allow_missing_client?(opts),
          do: :ok,
          else: {:error, :unauthorized_client}

      ^stored ->
        :ok

      _ ->
        {:error, :unauthorized_client}
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

  defp store_contract_error(:get), do: raise(RuntimeError, "refresh store get/1 violated its contract")

  defp store_contract_error(:revoke_family),
    do: raise(RuntimeError, "refresh store revoke_family/1 violated its contract")
end
