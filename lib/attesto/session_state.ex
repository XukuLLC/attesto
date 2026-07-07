defmodule Attesto.SessionState do
  @moduledoc """
  OpenID Connect Session Management 1.0 — the `session_state` value.

  Session Management lets a Relying Party poll, from JavaScript, whether the
  End-User's login state at the OP has changed without a network round trip:
  the RP posts `client_id + " " + session_state` to the OP's
  `check_session_iframe`, which recomputes the value from the *current* OP
  browser state and answers `unchanged` or `changed` (§3.1/§3.2).

  `session_state` is returned to the client as an additional authorization
  response parameter (§2) and is computed as (§3.2):

      hex(SHA256(client_id <> " " <> origin <> " " <> op_browser_state <> " " <> salt)) <> "." <> salt

    * `client_id` — the RP's client identifier.
    * `origin` — the origin of the Authentication Response's `redirect_uri`
      (see `origin/1`), which is what the browser reports as
      `MessageEvent.origin` when the RP's iframe posts to the OP iframe.
    * `op_browser_state` — the OP User Agent state: an opaque value stored in
      a JavaScript-readable cookie at the OP origin that changes on
      login/logout, so a recomputation with a stale value yields `changed`.
    * `salt` — a random per-response salt carried in cleartext after the `.`
      so the OP iframe can recompute the hash.

  The hash is lowercase hex, matching the §3.2 example's `CryptoJS.SHA256`
  string form, so the OP iframe's JavaScript recomputation compares equal. The
  value contains no space character (§2).

  Like the rest of attesto core this module is pure: the host owns the browser
  state cookie and the `check_session_iframe` page; this module owns the
  computation both sides must agree on.
  """

  # 128-bit values: the salt only needs to be unique per response, and the
  # browser state unguessable enough that it cannot be predicted cross-origin.
  @entropy_bytes 16

  @doc """
  Compute the `session_state` for an authorization response (§3.2).

  `origin` must be a browser-form origin (`scheme://host[:port]`, default port
  omitted) — derive it from the response's `redirect_uri` with `origin/1`.
  `salt` defaults to a fresh `generate_salt/0`.
  """
  @spec compute(String.t(), String.t(), String.t(), String.t()) :: String.t()
  def compute(client_id, origin, op_browser_state, salt \\ generate_salt())
      when is_binary(client_id) and is_binary(origin) and is_binary(op_browser_state) and is_binary(salt) do
    digest = :crypto.hash(:sha256, "#{client_id} #{origin} #{op_browser_state} #{salt}")
    Base.encode16(digest, case: :lower) <> "." <> salt
  end

  @doc """
  The browser-form origin of `uri` (RFC 6454): `scheme://host`, with the port
  appended only when it is not the scheme's default — exactly the string the
  browser reports as `MessageEvent.origin` for a page loaded from `uri`.

  Returns `{:ok, origin}` or `{:error, :invalid_uri}` for a URI with no
  scheme/host (a `session_state` computed over a malformed origin could never
  compare equal in the browser, so fail closed instead).
  """
  @spec origin(String.t()) :: {:ok, String.t()} | {:error, :invalid_uri}
  def origin(uri) when is_binary(uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host} = parsed
      when is_binary(scheme) and scheme != "" and is_binary(host) and host != "" ->
        {:ok, "#{scheme}://#{host}#{origin_port(scheme, parsed.port)}"}

      _ ->
        {:error, :invalid_uri}
    end
  end

  @doc "A fresh random salt for `compute/4` (unpadded URL-safe Base64, no spaces or dots)."
  @spec generate_salt() :: String.t()
  def generate_salt do
    @entropy_bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end

  @doc """
  A fresh OP browser state value.

  The host stores it in a JavaScript-readable cookie at the OP origin (§3.2 —
  the `check_session_iframe` script must read it, so `HttpOnly` cannot be set)
  and changes it when the End-User's login state changes (login/logout).
  """
  @spec generate_browser_state() :: String.t()
  def generate_browser_state do
    @entropy_bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end

  # A default port is omitted from a browser origin; any other port is kept.
  defp origin_port(scheme, port) do
    cond do
      is_nil(port) -> ""
      URI.default_port(scheme) == port -> ""
      true -> ":#{port}"
    end
  end
end
