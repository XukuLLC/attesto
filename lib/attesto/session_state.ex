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

  ## OP-owned, login-bound browser state

  The `session_state` recipe treats `op_browser_state` as an opaque string, so
  the OP is free to give that string internal structure. Session Management
  requires the OP browser state to be **OP-owned** (an RP-visible / injected
  value must not be able to forge `unchanged`) and to **change when the
  End-User's login state changes** (§3.2). `mint_browser_state/2` and
  `browser_state_valid?/3` give the value both properties without changing what
  the iframe hashes:

      random . login_tag . mac

    * `random` — fresh 128-bit entropy, unguessable cross-origin;
    * `login_tag` — `HMAC(secret, login_binding)`, a stable fingerprint of the
      current End-User login state (subject / auth_time / sid); a re-auth or
      account switch changes it, so a stale cookie fails `browser_state_valid?/3`
      and the OP rotates;
    * `mac` — `HMAC(secret, random . login_tag)`, so a value the OP did not mint
      (a cookie injected by a sibling/parent-domain origin) cannot verify.

  Only the OP knows `secret`. The whole `random . login_tag . mac` string is
  still what `compute/4` hashes as `op_browser_state`, so the iframe recipe is
  unchanged.
  """

  alias Attesto.SecureCompare

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
    validate_salt!(salt)
    digest = :crypto.hash(:sha256, "#{client_id} #{origin} #{op_browser_state} #{salt}")
    Base.encode16(digest, case: :lower) <> "." <> salt
  end

  # `generate_salt/0` always yields a safe base64url salt; this guards a
  # caller-supplied one. A space would put a space in the `session_state`
  # (§2 forbids it) and a `.` would fight the `hash "." salt` delimiter the OP
  # iframe splits on, so a value computed over such a salt could never compare
  # equal in the browser. Fail loudly at the source rather than emit it.
  defp validate_salt!(salt) do
    if salt == "" or String.contains?(salt, [" ", "."]) do
      raise ArgumentError,
            "session_state salt must be a non-empty string with no space or \".\" " <>
              "(use generate_salt/0); got: #{inspect(salt)}"
    end
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

  @doc """
  Mint an OP browser-state value that is OP-owned and bound to the End-User's
  current login state (see the module doc).

  `secret` is an OP-only HMAC key; `login_binding` is a caller-chosen string
  that captures the current login state (e.g. `subject`, `auth_time`, and `sid`
  joined together). The returned `random . login_tag . mac` string contains no
  space or `.`-ambiguity in its parts (each part is base64url-no-pad), so it is
  a valid `op_browser_state` for `compute/4` and splits back cleanly in
  `browser_state_valid?/3`.
  """
  @spec mint_browser_state(binary(), binary()) :: String.t()
  def mint_browser_state(secret, login_binding) when is_binary(secret) and is_binary(login_binding) do
    validate_secret!(secret)
    payload = generate_browser_state() <> "." <> login_tag(secret, login_binding)
    payload <> "." <> mac(secret, payload)
  end

  @doc """
  Whether `value` is an OP browser-state string this OP minted (under `secret`)
  for the current `login_binding`.

  Returns `false` — so the caller mints a fresh value — when either:

    * the value is malformed or its MAC does not verify: a value the OP never
      minted (a forged / cross-origin-injected cookie), which must not be
      trusted as authoritative browser state; or
    * the MAC verifies but the embedded `login_tag` is for a different login
      state: the End-User re-authenticated or switched accounts, so the OP
      browser state MUST rotate (Session Management 1.0 §3.2) and any earlier
      RP `session_state` becomes `changed`.

  Both comparisons go through `Attesto.SecureCompare.equal?/2`, so neither
  reveals HOW the presented value differs - wrong length, or right length and
  wrong bytes, take the same path. The segments come from an attacker-supplied
  string and are not length-validated first, so the time taken still varies
  with how much was submitted; see that module for the distinction.
  """
  @spec browser_state_valid?(binary(), binary(), binary()) :: boolean()
  def browser_state_valid?(secret, value, login_binding)
      when is_binary(secret) and is_binary(value) and is_binary(login_binding) do
    validate_secret!(secret)

    case String.split(value, ".", parts: 3) do
      [random, login_tag, mac] ->
        # Compute both comparisons before combining, so the result does not
        # depend on which one failed first. (The `mac` check already gates on a
        # secret-keyed value an attacker cannot forge, so this is hygiene, not a
        # load-bearing defence - but the boolean should still be work-uniform.)
        mac_ok = SecureCompare.equal?(mac, mac(secret, random <> "." <> login_tag))
        tag_ok = SecureCompare.equal?(login_tag, login_tag(secret, login_binding))
        mac_ok and tag_ok

      _ ->
        false
    end
  end

  # HMAC over the login binding, domain-separated from the value MAC. Rotating
  # when this tag changes is what makes an account switch / prompt=login /
  # max_age=0 re-auth flip a stale `session_state` to `changed` (§3.2).
  defp login_tag(secret, login_binding), do: hmac(secret, "attesto.opbs.login:" <> login_binding)

  # HMAC binding the OP as the author of `random . login_tag`, domain-separated
  # from the login tag. An injected/forged cookie cannot produce a verifying mac.
  defp mac(secret, payload), do: hmac(secret, "attesto.opbs.mac:" <> payload)

  defp hmac(secret, data) do
    :hmac |> :crypto.mac(:sha256, secret, data) |> Base.url_encode64(padding: false)
  end

  # HMAC-SHA256 accepts any key length, so an empty or short OP secret produces
  # a MAC an attacker can recompute (`:crypto.mac(:hmac, :sha256, "", data)` is
  # deterministic and needs no secret) - the browser state would no longer be
  # OP-owned. RFC 2104 §3 recommends a key at least as long as the hash output
  # (32 bytes for SHA-256). The secret is OP configuration, not attacker input,
  # so a too-short one is a misconfiguration to surface loudly, not tolerate.
  @min_secret_bytes 32
  defp validate_secret!(secret) do
    if byte_size(secret) < @min_secret_bytes do
      raise ArgumentError,
            "OP browser-state secret must be at least #{@min_secret_bytes} bytes " <>
              "(RFC 2104: an HMAC-SHA256 key shorter than the 32-byte output is weak); " <>
              "got #{byte_size(secret)} bytes"
    end
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
