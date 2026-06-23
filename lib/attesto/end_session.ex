defmodule Attesto.EndSession do
  @moduledoc """
  Validate an OpenID Connect RP-Initiated Logout request
  (OpenID Connect RP-Initiated Logout 1.0 §2-3).

  The end-session endpoint is where a Relying Party sends the End-User's
  browser to log out at the OP. Like the rest of attesto core this module is
  pure — it parses and validates the request parameters and never touches a
  store, a session, or a `Plug.Conn`. The host's controller owns loading the
  client, terminating the browser session, and (for Back-Channel Logout)
  fanning logout tokens out to the RPs.

  Two steps, because the second needs data the controller must fetch in
  between:

    1. `parse/2` validates the request parameters, verifies the
       `id_token_hint` (tolerating expiry — see
       `Attesto.IDToken.verify_logout_hint/2`), and resolves the Relying
       Party `client_id` and the session identifiers (`sub` / `sid`) the
       back-channel fan-out will key on. It returns a `t:t/0` the controller
       uses to load the client's registered `post_logout_redirect_uris`.
    2. `confirm_redirect/2` checks the requested `post_logout_redirect_uri`
       against that registered list (exact string match, RP-Initiated Logout
       §2/§3 — no normalization, no prefix matching) and returns the final
       redirect target with `state` appended, or `:no_redirect` when the RP
       asked for none.

  Resolving the client before validating the redirect URI is what makes an
  open-redirect impossible: a `post_logout_redirect_uri` is only ever honored
  when it exactly matches a value the client registered.
  """

  alias Attesto.Config
  alias Attesto.IDToken

  @typedoc """
  A parsed, hint-verified end-session request.

    * `:client_id` - the Relying Party, resolved from the `id_token_hint`'s
      `aud` and/or the `client_id` parameter (nil when the request carried
      neither, in which case no `post_logout_redirect_uri` can be honored).
    * `:subject` / `:sid` - the session identifiers from the `id_token_hint`
      (nil when no hint was supplied); the keys a Back-Channel Logout fan-out
      uses to find the RP sessions to notify.
    * `:post_logout_redirect_uri` / `:state` - the requested return target and
      opaque state, echoed back only after the URI is confirmed registered.
    * `:logout_hint` / `:ui_locales` - passthrough hints (RP-Initiated Logout
      §2) for the host's logout-confirmation UI.
  """
  @type t :: %__MODULE__{
          client_id: String.t() | nil,
          subject: String.t() | nil,
          sid: String.t() | nil,
          post_logout_redirect_uri: String.t() | nil,
          state: String.t() | nil,
          logout_hint: String.t() | nil,
          ui_locales: String.t() | nil
        }

  defstruct [
    :client_id,
    :subject,
    :sid,
    :post_logout_redirect_uri,
    :state,
    :logout_hint,
    :ui_locales
  ]

  @type parse_error :: :invalid_id_token_hint | :client_id_mismatch

  @doc """
  Parse and validate the end-session request `params` (string- or atom-keyed).

  Recognized parameters (OpenID Connect RP-Initiated Logout 1.0 §2):
  `id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state`,
  `logout_hint`, `ui_locales`.

  When `id_token_hint` is present it is verified via
  `Attesto.IDToken.verify_logout_hint/2` (signature + issuer, expiry
  tolerated); a hint that fails verification is `:invalid_id_token_hint`. The
  Relying Party `client_id` is taken from the hint's `aud`; if the `client_id`
  parameter is **also** present it MUST equal it (`:client_id_mismatch`,
  RP-Initiated Logout §2). With no hint, the `client_id` parameter alone
  identifies the RP.

  Returns `{:ok, %Attesto.EndSession{}}` or `{:error, reason}`.
  """
  @spec parse(Config.t(), map()) :: {:ok, t()} | {:error, parse_error()}
  def parse(%Config{} = config, params) when is_map(params) do
    hint = param(params, "id_token_hint")
    client_id_param = param(params, "client_id")

    with {:ok, claims} <- verify_hint(config, hint),
         {:ok, client_id} <- resolve_client_id(claims, client_id_param) do
      {:ok,
       %__MODULE__{
         client_id: client_id,
         subject: claim(claims, "sub"),
         sid: claim(claims, "sid"),
         post_logout_redirect_uri: param(params, "post_logout_redirect_uri"),
         state: param(params, "state"),
         logout_hint: param(params, "logout_hint"),
         ui_locales: param(params, "ui_locales")
       }}
    end
  end

  @doc """
  Confirm the request's `post_logout_redirect_uri` against the Relying Party's
  registered list and compute the final redirect target.

  `registered_uris` is the client's registered `post_logout_redirect_uris`
  (the host loads them from its `Attesto.ClientStore` between `parse/2` and
  this call). Matching is exact-string (RP-Initiated Logout §2/§3).

  Returns:

    * `{:ok, :no_redirect}` - the request asked for no return URI; the host
      should render its own logged-out page.
    * `{:ok, url}` - the validated `post_logout_redirect_uri` with the
      request's `state` appended as a query parameter when present.
    * `{:error, :invalid_post_logout_redirect_uri}` - the requested URI is not
      registered (or the RP could not be identified), so it MUST NOT be used.
  """
  @spec confirm_redirect(t(), [String.t()]) ::
          {:ok, String.t() | :no_redirect} | {:error, :invalid_post_logout_redirect_uri}
  def confirm_redirect(%__MODULE__{post_logout_redirect_uri: nil}, _registered), do: {:ok, :no_redirect}

  def confirm_redirect(%__MODULE__{post_logout_redirect_uri: requested} = request, registered)
      when is_binary(requested) and is_list(registered) do
    if requested in registered,
      do: {:ok, append_state(requested, request.state)},
      else: {:error, :invalid_post_logout_redirect_uri}
  end

  # ----- internal -----

  defp verify_hint(_config, nil), do: {:ok, %{}}
  defp verify_hint(_config, ""), do: {:ok, %{}}

  defp verify_hint(config, hint) when is_binary(hint) do
    case IDToken.verify_logout_hint(config, hint) do
      {:ok, claims} -> {:ok, claims}
      {:error, _reason} -> {:error, :invalid_id_token_hint}
    end
  end

  # The RP is the hint's `aud` (a single string for an ID Token; the first
  # entry of an array audience). If the `client_id` parameter is also given it
  # MUST agree (RP-Initiated Logout §2).
  defp resolve_client_id(claims, client_id_param) do
    hint_client = audience_client(Map.get(claims, "aud"))

    cond do
      is_binary(hint_client) and is_binary(client_id_param) and hint_client != client_id_param ->
        {:error, :client_id_mismatch}

      is_binary(hint_client) ->
        {:ok, hint_client}

      is_binary(client_id_param) and client_id_param != "" ->
        {:ok, client_id_param}

      true ->
        {:ok, nil}
    end
  end

  defp audience_client(aud) when is_binary(aud) and aud != "", do: aud
  defp audience_client([aud | _]) when is_binary(aud) and aud != "", do: aud
  defp audience_client(_), do: nil

  # Append `state` to the validated redirect URI, preserving any query the RP
  # already registered on it (RP-Initiated Logout §3).
  defp append_state(uri, nil), do: uri
  defp append_state(uri, ""), do: uri

  defp append_state(uri, state) when is_binary(state) do
    parsed = URI.parse(uri)
    query = URI.decode_query(parsed.query || "") |> Map.put("state", state)
    parsed |> Map.put(:query, URI.encode_query(query)) |> URI.to_string()
  end

  defp param(params, key) do
    case Map.get(params, key) || Map.get(params, String.to_atom(key)) do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp claim(claims, key) do
    case Map.get(claims, key) do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end
end
