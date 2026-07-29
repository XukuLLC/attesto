defmodule Attesto.RedirectURITest do
  use ExUnit.Case, async: true

  alias Attesto.RedirectURI

  describe "matching_modes/0" do
    test "lists exactly the modes registered?/3 accepts" do
      assert RedirectURI.matching_modes() == [:exact, :exact_allow_loopback_port]
    end
  end

  describe "matching!/1" do
    test "passes a supported mode through" do
      assert RedirectURI.matching!(:exact) == :exact
      assert RedirectURI.matching!(:exact_allow_loopback_port) == :exact_allow_loopback_port
    end

    test "raises on an unrecognized mode rather than silently picking a policy" do
      assert_raise ArgumentError, ~r/invalid redirect_uri matching mode :loopback/, fn ->
        RedirectURI.matching!(:loopback)
      end

      assert_raise ArgumentError, fn -> RedirectURI.matching!(nil) end
      assert_raise ArgumentError, fn -> RedirectURI.matching!("exact") end
    end
  end

  describe "registered?/3 with :exact (RFC 6749 §3.1.2.3)" do
    test "matches byte-for-byte" do
      assert RedirectURI.registered?("https://app.example/cb", ["https://app.example/cb"], :exact)
    end

    test "defaults to :exact when no mode is given" do
      assert RedirectURI.registered?("https://app.example/cb", ["https://app.example/cb"])
      refute RedirectURI.registered?("https://app.example/cb", ["https://app.example/cb/"])
    end

    test "does not normalize case, trailing slash, or default ports" do
      registered = ["https://app.example/cb"]

      refute RedirectURI.registered?("https://APP.example/cb", registered, :exact)
      refute RedirectURI.registered?("https://app.example/cb/", registered, :exact)
      refute RedirectURI.registered?("https://app.example:443/cb", registered, :exact)
    end

    test "an empty registered set matches nothing" do
      refute RedirectURI.registered?("https://app.example/cb", [], :exact)
    end

    test "ignores a non-binary registered entry instead of raising" do
      assert RedirectURI.registered?("https://app.example/cb", [nil, :atom, "https://app.example/cb"], :exact)
      refute RedirectURI.registered?("https://app.example/cb", [nil, :atom], :exact)
    end

    test "never applies the loopback exception" do
      refute RedirectURI.registered?("http://127.0.0.1:51823/cb", ["http://127.0.0.1:0/cb"], :exact)
      refute RedirectURI.registered?("http://[::1]:51823/cb", ["http://[::1]/cb"], :exact)
    end
  end

  describe "registered?/3 with :exact_allow_loopback_port (RFC 8252 §7.3)" do
    test "an exact match still wins" do
      assert RedirectURI.registered?(
               "https://app.example/cb",
               ["https://app.example/cb"],
               :exact_allow_loopback_port
             )
    end

    test "an IPv4 loopback request matches any registered loopback port" do
      for registered <- ["http://127.0.0.1:0/cb", "http://127.0.0.1/cb", "http://127.0.0.1:8080/cb"] do
        assert RedirectURI.registered?("http://127.0.0.1:51823/cb", [registered], :exact_allow_loopback_port),
               "expected #{registered} to match a request on port 51823"
      end
    end

    test "an IPv6 loopback request behaves identically to the IPv4 case" do
      for registered <- ["http://[::1]:0/cb", "http://[::1]/cb", "http://[::1]:8080/cb"] do
        assert RedirectURI.registered?("http://[::1]:51823/cb", [registered], :exact_allow_loopback_port),
               "expected #{registered} to match a request on port 51823"
      end
    end

    test "IPv4 and IPv6 loopback are distinct hosts" do
      refute RedirectURI.registered?("http://[::1]:51823/cb", ["http://127.0.0.1:0/cb"], :exact_allow_loopback_port)
      refute RedirectURI.registered?("http://127.0.0.1:51823/cb", ["http://[::1]:0/cb"], :exact_allow_loopback_port)
    end

    test "the path must still match exactly" do
      registered = ["http://127.0.0.1:0/cb"]

      refute RedirectURI.registered?("http://127.0.0.1:51823/other", registered, :exact_allow_loopback_port)
      refute RedirectURI.registered?("http://127.0.0.1:51823/cb/", registered, :exact_allow_loopback_port)
      refute RedirectURI.registered?("http://127.0.0.1:51823/cb/sub", registered, :exact_allow_loopback_port)
      refute RedirectURI.registered?("http://127.0.0.1:51823", registered, :exact_allow_loopback_port)
    end

    test "the query must still match exactly" do
      refute RedirectURI.registered?(
               "http://127.0.0.1:51823/cb?a=2",
               ["http://127.0.0.1:0/cb?a=1"],
               :exact_allow_loopback_port
             )

      refute RedirectURI.registered?(
               "http://127.0.0.1:51823/cb",
               ["http://127.0.0.1:0/cb?a=1"],
               :exact_allow_loopback_port
             )

      assert RedirectURI.registered?(
               "http://127.0.0.1:51823/cb?a=1",
               ["http://127.0.0.1:0/cb?a=1"],
               :exact_allow_loopback_port
             )
    end

    # RFC 8252 §8.3: the literal IP address is required; `localhost` is NOT
    # acceptable, because any application on the device may claim the name.
    test "localhost is rejected in every form" do
      for uri <- ["http://localhost:51823/cb", "http://localhost/cb"] do
        refute RedirectURI.registered?(uri, ["http://127.0.0.1:0/cb"], :exact_allow_loopback_port)
        refute RedirectURI.registered?(uri, ["http://localhost:0/cb"], :exact_allow_loopback_port)
        refute RedirectURI.registered?("http://127.0.0.1:51823/cb", [uri], :exact_allow_loopback_port)
      end

      # A registered `localhost` URI is still reachable by exact match; it just
      # gets no port flexibility.
      assert RedirectURI.registered?(
               "http://localhost:51823/cb",
               ["http://localhost:51823/cb"],
               :exact_allow_loopback_port
             )
    end

    test "https loopback is not relaxed" do
      refute RedirectURI.registered?(
               "https://127.0.0.1:51823/cb",
               ["https://127.0.0.1:0/cb"],
               :exact_allow_loopback_port
             )

      refute RedirectURI.registered?("https://[::1]:51823/cb", ["https://[::1]:0/cb"], :exact_allow_loopback_port)
    end

    test "a remote host is not relaxed" do
      refute RedirectURI.registered?(
               "https://example.com:8443/cb",
               ["https://example.com:443/cb"],
               :exact_allow_loopback_port
             )

      refute RedirectURI.registered?(
               "http://example.com:8443/cb",
               ["http://example.com/cb"],
               :exact_allow_loopback_port
             )
    end

    test "a private-use URI scheme redirect is unaffected" do
      registered = ["com.example.app:/cb"]

      assert RedirectURI.registered?("com.example.app:/cb", registered, :exact_allow_loopback_port)
      assert RedirectURI.registered?("com.example.app:/cb", registered, :exact)
      refute RedirectURI.registered?("com.example.app:/other", registered, :exact_allow_loopback_port)
    end

    # The exception is keyed on the byte-exact `http://` prefix, so a scheme
    # spelled differently is outside it and stays exact-match.
    test "an upper-case scheme is outside the exception" do
      refute RedirectURI.registered?("HTTP://127.0.0.1:51823/cb", ["http://127.0.0.1:0/cb"], :exact_allow_loopback_port)
      refute RedirectURI.registered?("http://127.0.0.1:51823/cb", ["HTTP://127.0.0.1:0/cb"], :exact_allow_loopback_port)
    end

    test "userinfo takes the URI outside the exception" do
      refute RedirectURI.registered?(
               "http://evil.example@127.0.0.1:51823/cb",
               ["http://127.0.0.1:0/cb"],
               :exact_allow_loopback_port
             )

      # The authority here parses as userinfo `127.0.0.1:51823` on host
      # `evil.example`; the loopback literal appearing in the string must not
      # buy any relaxation.
      refute RedirectURI.registered?(
               "http://127.0.0.1:51823@evil.example/cb",
               ["http://127.0.0.1:0/cb"],
               :exact_allow_loopback_port
             )
    end

    test "an alternative spelling of the loopback address is outside the exception" do
      registered = ["http://127.0.0.1:0/cb"]

      for uri <- [
            "http://0177.0.0.1:51823/cb",
            "http://2130706433:51823/cb",
            "http://127.0.0.1.:51823/cb",
            "http://127.0.0.2:51823/cb",
            "http://127.1:51823/cb",
            "http://[0:0:0:0:0:0:0:1]:51823/cb"
          ] do
        refute RedirectURI.registered?(uri, registered, :exact_allow_loopback_port),
               "expected #{uri} to fall outside the RFC 8252 §7.3 exception"
      end

      refute RedirectURI.registered?(
               "http://[::1]:51823/cb",
               ["http://[0:0:0:0:0:0:0:1]:0/cb"],
               :exact_allow_loopback_port
             )
    end

    test "a fragment takes the URI outside the exception" do
      refute RedirectURI.registered?(
               "http://127.0.0.1:51823/cb#f",
               ["http://127.0.0.1:0/cb"],
               :exact_allow_loopback_port
             )

      refute RedirectURI.registered?(
               "http://127.0.0.1:51823/cb",
               ["http://127.0.0.1:0/cb#f"],
               :exact_allow_loopback_port
             )
    end

    test "a malformed port takes the URI outside the exception" do
      refute RedirectURI.registered?("http://127.0.0.1:abc/cb", ["http://127.0.0.1:0/cb"], :exact_allow_loopback_port)
    end

    # The request URI is a redirect TARGET, so a port it carries must be one a
    # client can actually listen on. An unusable port is not minted into a
    # Location header just because the rest of the URI looks like loopback.
    test "a request port outside 1..65535 takes the URI outside the exception" do
      # Registered with a port none of the refused URIs reproduce, so an exact
      # match cannot rescue them and only the exception is under test.
      registered = ["http://127.0.0.1:8080/cb"]

      for uri <- [
            "http://127.0.0.1:/cb",
            "http://127.0.0.1:0/cb",
            "http://127.0.0.1:65536/cb",
            "http://127.0.0.1:999999999999999999999/cb"
          ] do
        refute RedirectURI.registered?(uri, registered, :exact_allow_loopback_port),
               "expected request port in #{uri} to be refused"
      end

      # The boundaries themselves are usable.
      assert RedirectURI.registered?("http://127.0.0.1:1/cb", registered, :exact_allow_loopback_port)
      assert RedirectURI.registered?("http://127.0.0.1:65535/cb", registered, :exact_allow_loopback_port)
    end

    # The registered URI is a pattern, never a target: its port is discarded, so
    # the `:0` placeholder convention keeps working.
    test "the registered side accepts any port, including the :0 placeholder" do
      for registered <- ["http://127.0.0.1:0/cb", "http://127.0.0.1:/cb", "http://127.0.0.1:99999999/cb"] do
        assert RedirectURI.registered?("http://127.0.0.1:51823/cb", [registered], :exact_allow_loopback_port),
               "expected registered #{registered} to still match a usable request port"
      end
    end

    # `http://127.0.0.1:0/cb` as a REQUEST is refused by the exception, but an
    # exact registration of it still matches exactly - the exception only ever
    # adds matches.
    test "an exact match still wins for a request port the exception would refuse" do
      assert RedirectURI.registered?(
               "http://127.0.0.1:0/cb",
               ["http://127.0.0.1:0/cb"],
               :exact_allow_loopback_port
             )
    end

    test "an empty registered set still matches nothing" do
      refute RedirectURI.registered?("http://127.0.0.1:51823/cb", [], :exact_allow_loopback_port)
    end

    test "a non-loopback request never matches a loopback registration" do
      refute RedirectURI.registered?("https://evil.example/cb", ["http://127.0.0.1:0/cb"], :exact_allow_loopback_port)
    end
  end

  describe "unambiguous?/1" do
    test "admits ordinary redirect URIs" do
      for uri <- [
            "https://client.example/cb",
            "https://client.example:8443/cb?a=1",
            "http://127.0.0.1:51823/cb",
            "http://[::1]/cb",
            "com.example.app:/oauth2redirect",
            "com.example.app://callback"
          ] do
        assert RedirectURI.unambiguous?(uri), "expected #{inspect(uri)} to be admitted"
      end
    end

    # The finding this predicate exists for: RFC 3986 reads `evil.example\` as
    # userinfo and `client.example` as the host, so an origin check phrased in
    # terms of `URI.parse/1` approves it - while a browser terminates the
    # authority at the backslash and navigates to `evil.example`.
    test "refuses a backslash, whichever host each parser ends up reading" do
      for uri <- [
            "https://evil.example\\@client.example/cb",
            "https://client.example\\@evil.example/cb",
            "https://client.example/cb\\@evil.example",
            "http://127.0.0.1\\@evil.example/cb"
          ] do
        refute RedirectURI.unambiguous?(uri), "expected #{inspect(uri)} to be refused"
      end
    end

    # Userinfo has no legitimate place in a redirect URI, and every authority
    # confusion trick is built from it. Refused as a class rather than only in
    # the spellings currently known to differ between parsers.
    test "refuses userinfo even where the parsers agree" do
      refute RedirectURI.unambiguous?("https://evil.example@client.example/cb")
      refute RedirectURI.unambiguous?("https://user:pw@client.example/cb")
      refute RedirectURI.unambiguous?("https://@client.example/cb")
    end

    test "an `@` in the path is not userinfo and stays admissible" do
      assert RedirectURI.unambiguous?("https://client.example/@handle/cb")
      assert RedirectURI.unambiguous?("https://client.example/cb?to=a@b")
    end

    # WHATWG strips tab/CR/LF before parsing and percent-encodes other control
    # characters; RFC 3986 does neither, so the two can disagree about where
    # the authority ends.
    test "refuses control characters and whitespace" do
      for uri <- [
            "https://evil.example\t@client.example/cb",
            "https://evil.example\n@client.example/cb",
            "https://evil.example\r@client.example/cb",
            "https://client.example/c b",
            "https://client.example/cb\0",
            "https://client.example/cb\x7f"
          ] do
        refute RedirectURI.unambiguous?(uri), "expected #{inspect(uri)} to be refused"
      end
    end

    test "refuses anything that is not a parseable binary" do
      refute RedirectURI.unambiguous?("https://client.example/cb|pipe")
      refute RedirectURI.unambiguous?(nil)
      refute RedirectURI.unambiguous?(:uri)
      refute RedirectURI.unambiguous?(["https://client.example/cb"])
    end

    # The predicate governs what may be REGISTERED; it is not a matching mode
    # and must not quietly change what `registered?/3` accepts.
    test "does not affect matching, which stays byte-exact" do
      ambiguous = "https://evil.example\\@client.example/cb"

      assert RedirectURI.registered?(ambiguous, [ambiguous], :exact)
      refute RedirectURI.unambiguous?(ambiguous)
    end
  end
end
