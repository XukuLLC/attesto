defmodule Attesto.RedirectURI do
  @moduledoc """
  Redirect-URI matching for the authorization endpoint (RFC 6749 §3.1.2.3,
  RFC 8252 §7.3).

  RFC 6749 §3.1.2.3 matches a request `redirect_uri` against the client's
  registered set by **simple string comparison**: byte-for-byte, no
  normalization and no prefix matching. That is the default here, and it is what
  the OpenID Connect and FAPI profiles assume.

  RFC 8252 (BCP 212) defines one narrow exception. A native application that
  cannot use a private-use URI scheme (§7.1) instead binds an ephemeral port on
  the loopback interface (§7.3) and only learns that port at runtime, so the
  port cannot be registered ahead of time. §7.3 therefore requires the
  authorization server to "allow any port to be specified at the time of the
  request for loopback IP redirect URIs", while comparing the rest of the URI
  exactly.

  ## Matching modes

    * `:exact` (default) - RFC 6749 §3.1.2.3 simple string comparison, and
      nothing else.

    * `:exact_allow_loopback_port` - exact comparison first; failing that, the
      RFC 8252 §7.3 loopback exception. The exception applies only when BOTH the
      request URI and the registered URI are loopback redirect URIs, meaning
      each one:

        * begins with the byte-exact scheme `http://` (an `https` URI, a
          private-use scheme, and an upper-case `HTTP://` are all outside the
          exception and stay exact-match);
        * has an authority of exactly `127.0.0.1` or `[::1]`, optionally
          followed by `:<port>` and nothing else. Any userinfo, any other host,
          and any other spelling of the loopback address are outside the
          exception.

          `localhost` is deliberately excluded. RFC 8252 §8.3 makes the literal
          IP preferable precisely because `localhost` is a *name*, resolved by
          the device's host-name configuration, and so is not guaranteed to be
          the loopback interface. Extending port flexibility to a name whose
          resolution the server cannot reason about would widen the exception
          past what §7.3 asks for, so `http://localhost:PORT/...` never matches
          under it.

          RFC 9700 §2.1 and §4.1.3 phrase the same exception as applying to
          "`localhost` redirection URIs of native apps", which reads as a wider
          allowance. Both, however, define it by reference - "as described in
          Section 7.3 of [RFC8252]" - and §7.3 constructs the URI from the
          loopback IP literal, not the name. `localhost` there is shorthand for
          "the loopback interface", so the normative content is §7.3's and this
          module follows it. A client that has registered a `localhost` URI is
          unaffected in the ordinary case: it still matches exactly, it just
          gets no port flexibility.

          This scopes the exception, not registration: a client that has
          registered a `localhost` redirect URI still reaches it by exact
          match, since that URI is one the host deliberately registered and
          §8.3's "NOT RECOMMENDED" is guidance to the client about which URI to
          choose, not a requirement that the server refuse it. Such a client
          simply gets no port flexibility;
        * carries no fragment (a redirect URI must not, RFC 6749 §3.1.2).

      The two sides differ in one respect. The **request** URI names an
      endpoint the server is about to redirect a browser to, so a port it
      carries must be decimal `1..65535` or absent; an empty
      (`http://127.0.0.1:/cb`) or out-of-range port is not a reachable endpoint
      and falls back to exact comparison. The **registered** URI is a pattern
      whose port is discarded, so any port stands there - including the
      conventional `:0` placeholder for "an ephemeral port chosen at runtime".

      Two loopback URIs match when their scheme, host literal, path, and query
      are all identical; only the port is ignored. IPv4 and IPv6 loopback are
      distinct hosts and never match each other.

    * `:exact_allow_loopback_port_including_localhost` - everything
      `:exact_allow_loopback_port` does, and additionally treats the bare
      hostname `localhost` as a loopback authority, so
      `http://localhost:<ephemeral>/cb` matches a registered
      `http://localhost/cb`.

      This exists for interoperability, not because §7.3 requires it. §7.3's
      MUST is scoped to "loopback IP redirect URIs" and the paragraphs above
      are the right default. But nothing forbids a server allowing the name,
      and §8.3's case against `localhost` is stated entirely in terms of what
      the *client* does - it "avoids inadvertently listening on network
      interfaces other than the loopback interface" and is "less susceptible to
      client-side firewalls and misconfigured host name resolution on the
      user's device". Those are reasons for an app author to choose the IP
      literal; refusing port flexibility at the authorization server does not
      make any of them true, it only fails the request. Real native clients
      exist that register a portless `localhost` callback and then bind an
      ephemeral port, and they cannot authorize at all under the stricter rule.

      The residual risk is bounded by two allowances this module already makes
      independently: a registered `localhost` URI is already reachable by exact
      match, so redirecting to a name the server cannot resolve is already
      accepted; and §7.3 already mandates port flexibility, so a code landing
      on an arbitrary local port is already accepted for `127.0.0.1`. This mode
      permits their combination and nothing else, which is why it is a separate
      opt-in rather than a relaxation of `:exact_allow_loopback_port`.

      `localhost` is its own host identity, never folded onto `127.0.0.1`: the
      name and the IP literals do not cross-match, exactly as IPv4 and IPv6
      loopback do not. Every other constraint above is unchanged - byte-exact
      `http://` scheme, anchored authority (so `localhost.evil.example`,
      `sub.localhost`, `evil-localhost`, `localhost.` and any userinfo stay
      outside), no fragment, exact path and query, and the same asymmetric port
      rule between the request and registered sides.

  Enabling either exception is a deliberate deployment decision: a profile that
  mandates exact redirect-URI matching forbids them. Both are off by default so
  the matching behavior is unchanged unless a host asks for it.

  ## Registration convention

  A client registers its loopback redirect URI with whatever port it likes
  (`http://127.0.0.1/cb`, `http://127.0.0.1:0/cb`, or a fixed port) and any
  usable request port then matches. Only the port is variable; a request that
  differs in path or query is still rejected.

  ## Failure is never a redirect

  This module answers a boolean. A request URI that matches nothing is not a
  trusted redirect target, and the caller MUST report the failure directly to
  the user agent rather than redirecting to the supplied URI (OIDC Core
  §3.1.2.6) - otherwise the endpoint is an open redirect.

  ## Parser agreement

  Matching is only as sound as the agreement between the parser that *decides*
  and the parser that *navigates*. Elixir's `URI` follows RFC 3986; the browser
  that receives the `Location` follows the WHATWG URL Standard, and the two
  disagree about some authorities. In `https://evil.example\\@client.example/cb`,
  RFC 3986 reads `evil.example\\` as userinfo and `client.example` as the host,
  while WHATWG treats the backslash as a path separator and navigates to
  `evil.example`.

  Byte-exact matching is immune - it compares strings, never origins - and the
  §7.3 loopback exception is immune because it anchors on the whole authority
  rather than the parsed host. Any check phrased in terms of a *host* or an
  *origin* is not, so `unambiguous?/1` exists to keep such a URI out of a
  registered set in the first place.
  """

  @typedoc "The redirect-URI matching mode (see the moduledoc)."
  @type matching :: :exact | :exact_allow_loopback_port | :exact_allow_loopback_port_including_localhost

  @matching_modes [:exact, :exact_allow_loopback_port, :exact_allow_loopback_port_including_localhost]

  # RFC 8252 §7.3 covers only `http` on the loopback interface: the connection
  # never leaves the device, so TLS is neither available nor required there.
  # Compared as a byte-exact prefix rather than through the parsed scheme, so
  # the exception cannot be reached by a case variant the exact-match rule would
  # otherwise have rejected.
  @http_scheme_prefix "http://"

  # RFC 8252 §7.3 / §8.3: the authority of a loopback redirect URI is the
  # literal IPv4 or IPv6 loopback address with an optional port, and nothing
  # else. Anchored, so userinfo (`user@127.0.0.1`), a different host, a trailing
  # dot (`127.0.0.1.`), an alternative encoding (`0177.0.0.1`, `[0:0:0:0:0:0:0:1]`),
  # and the hostname `localhost` (§8.3: NOT acceptable) all fail to match and
  # fall back to exact comparison. The port is captured rather than skipped so
  # `port_allowed?/2` can hold the request side to a usable range.
  @loopback_authority ~r/\A(127\.0\.0\.1|\[::1\])(?::([0-9]*))?\z/

  # The same authority, plus the hostname `localhost`, for
  # `:exact_allow_loopback_port_including_localhost` only. Anchored on the whole
  # authority exactly as above, so `localhost.evil.example`, `sub.localhost`,
  # `evil-localhost`, a trailing dot (`localhost.`) and userinfo
  # (`evil.example@localhost`) all stay outside the exception - only the bare
  # name, optionally followed by a port, is loopback. Byte-exact like every
  # other comparison here, so `LOCALHOST` is not the same host as `localhost`.
  #
  # `localhost` is captured as itself rather than folded onto `127.0.0.1`, so
  # the name and the IP literals remain distinct identities and never
  # cross-match. A client that registers one does not thereby reach the other.
  @loopback_authority_including_localhost ~r/\A(127\.0\.0\.1|\[::1\]|localhost)(?::([0-9]*))?\z/

  # A TCP port a client can actually bind and be redirected to. Port 0 is
  # excluded on the request side: it is the "pick one for me" placeholder, not
  # an endpoint a browser can reach.
  @min_port 1
  @max_port 65_535

  # The bytes whose treatment differs between RFC 3986 and the WHATWG URL
  # Standard (see `unambiguous?/1`): C0 controls, space, and the backslash.
  # Matched against the raw string rather than a parsed component, since the
  # disagreement is precisely about where the components begin and end.
  @ambiguous_bytes ~r/[\x00-\x20\x7f\\]/

  @doc """
  The supported matching modes. Exposed so a caller can validate host
  configuration against the same list this module enforces.
  """
  @spec matching_modes() :: [matching()]
  def matching_modes, do: @matching_modes

  @doc """
  Normalize a caller-supplied matching mode, raising `ArgumentError` on an
  unrecognized value.

  A misspelled mode must never silently degrade into a different matching
  policy, in either direction: quietly falling back to `:exact` would hide a
  host's deliberate opt-in, and quietly enabling anything else would relax
  matching nobody asked for. Raising makes the misconfiguration visible.
  """
  @spec matching!(term()) :: matching()
  def matching!(matching) when matching in @matching_modes, do: matching

  def matching!(other) do
    raise ArgumentError,
          "invalid redirect_uri matching mode #{inspect(other)}; expected one of #{inspect(@matching_modes)}"
  end

  @doc """
  Whether every URL parser agrees which origin `uri` names (see "Parser
  agreement" in the moduledoc).

  Answers `false` for a URI carrying anything that makes RFC 3986 and the WHATWG
  URL Standard read a different authority out of the same bytes:

    * a **backslash** anywhere. WHATWG maps `\\` to `/` in a special scheme, so
      it can terminate an authority that RFC 3986 reads as continuing.
    * **userinfo**. `https://a@b/` is unambiguous today, but userinfo is the
      component every authority-confusion trick is built out of, and a redirect
      URI has no legitimate use for credentials (RFC 6749 §3.1.2 wants a plain
      absolute URI). Refusing it removes the whole class rather than the one
      spelling known to differ.
    * a **C0 control, space, tab, CR, or LF**. WHATWG strips tab/CR/LF before
      parsing and percent-encodes the rest; RFC 3986 does neither.

  A URI that does not parse at all is likewise `false` - it is not a target the
  server can reason about.

  This is a check on what may be *registered*, not a matching mode. It says
  nothing about whether a URI is a good redirect target, only that the answer
  will not depend on which parser is asked.
  """
  @spec unambiguous?(term()) :: boolean()
  def unambiguous?(uri) when is_binary(uri) do
    not Regex.match?(@ambiguous_bytes, uri) and no_userinfo?(uri)
  end

  def unambiguous?(_uri), do: false

  defp no_userinfo?(uri) do
    case URI.new(uri) do
      {:ok, %URI{userinfo: nil}} -> true
      _ -> false
    end
  end

  @doc """
  Whether `uri` matches one of the client's `registered` redirect URIs under
  `matching` (RFC 6749 §3.1.2.3, RFC 8252 §7.3).

  A non-binary entry in `registered` is ignored rather than raising: the
  registered set comes from the host, and one malformed entry must not make an
  otherwise valid request crash the endpoint.
  """
  @spec registered?(String.t(), [String.t()], matching()) :: boolean()
  def registered?(uri, registered, matching \\ :exact)

  def registered?(uri, registered, :exact) when is_binary(uri) and is_list(registered) do
    exact?(uri, registered)
  end

  def registered?(uri, registered, :exact_allow_loopback_port) when is_binary(uri) and is_list(registered) do
    # RFC 8252 §7.3 is an exception applied only after the RFC 6749 §3.1.2.3
    # comparison has already failed, so enabling it can never change the outcome
    # of a request that matched exactly.
    exact?(uri, registered) or loopback?(uri, registered, @loopback_authority)
  end

  def registered?(uri, registered, :exact_allow_loopback_port_including_localhost)
      when is_binary(uri) and is_list(registered) do
    exact?(uri, registered) or loopback?(uri, registered, @loopback_authority_including_localhost)
  end

  # Exact string comparison (RFC 6749 §3.1.2.3 simple string match). No
  # normalization, no prefix matching: a registered URI must be reproduced
  # byte-for-byte, the same discipline `Attesto.AuthorizationCode` applies to
  # the redemption-time `redirect_uri` check.
  defp exact?(uri, registered) do
    Enum.any?(registered, fn candidate -> is_binary(candidate) and candidate == uri end)
  end

  # RFC 8252 §7.3: a loopback request URI matches a registered loopback URI
  # whose scheme, host literal, path, and query are identical. `nil` from
  # `loopback_identity/2` means "not a loopback redirect URI", which never
  # matches anything - including another non-loopback URI, since the request
  # side is checked first and short-circuits.
  # `authority` is the pattern defining which hosts count as loopback, so the
  # mode - not this function - decides whether the `localhost` name is one.
  defp loopback?(uri, registered, authority) do
    case loopback_identity(uri, :request, authority) do
      nil ->
        false

      identity ->
        Enum.any?(registered, fn candidate ->
          is_binary(candidate) and loopback_identity(candidate, :registered, authority) == identity
        end)
    end
  end

  # The port-independent identity of a loopback redirect URI, or `nil` when the
  # URI is not one. The port is the only component omitted; everything else that
  # distinguishes one redirect target from another (host literal, path, query)
  # is carried, so two URIs share an identity only when they differ solely in
  # port.
  #
  # `role` distinguishes the two sides, which are not symmetric in what a port
  # may be. The REQUEST URI names an endpoint the authorization server is about
  # to redirect a browser to, so a port it carries must be one a client can
  # actually listen on: absent, or decimal 1-65535. An empty port
  # (`http://127.0.0.1:/cb`) or an out-of-range one
  # (`http://127.0.0.1:999999999/cb`) is not a reachable endpoint and falls back
  # to exact comparison rather than being minted a redirect target.
  #
  # The REGISTERED URI is a pattern, never a target: its port is discarded by
  # construction, so any port stands. That is deliberate - `:0` is the
  # conventional placeholder for "an ephemeral port chosen at runtime", and
  # rejecting it would break the natural way to register a loopback callback.
  defp loopback_identity(uri, role, authority) do
    if String.starts_with?(uri, @http_scheme_prefix) do
      uri |> URI.parse() |> identity(role, authority)
    end
  end

  defp identity(%URI{authority: authority, path: path, query: query, fragment: nil}, role, pattern)
       when is_binary(authority) do
    case Regex.run(pattern, authority) do
      [_authority, host] -> {host, path, query}
      [_authority, host, port] -> if port_allowed?(port, role), do: {host, path, query}
      nil -> nil
    end
  end

  defp identity(%URI{}, _role, _pattern), do: nil

  defp port_allowed?(_port, :registered), do: true

  defp port_allowed?(port, :request) do
    case Integer.parse(port) do
      {number, ""} -> number in @min_port..@max_port
      _ -> false
    end
  end
end
