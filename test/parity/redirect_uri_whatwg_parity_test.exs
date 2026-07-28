defmodule Attesto.Parity.RedirectURIWhatwgParityTest do
  @moduledoc false
  # Cross-parser CONTRACT parity for RFC 8252 §7.3 loopback redirect matching.
  #
  # `Attesto.RedirectURI` decides whether a request `redirect_uri` may be used
  # as a redirect target. It reaches that decision through Elixir's `URI.parse/1`,
  # an RFC 3986 parser. The user agent that ultimately follows the `Location`
  # header does NOT use an RFC 3986 parser - browsers implement the WHATWG URL
  # Standard, and the two disagree on real inputs (a backslash in the authority
  # is the clearest case: RFC 3986 reads what follows as a host, WHATWG
  # terminates the authority and folds the rest into the path).
  #
  # A disagreement in one direction is a vulnerability and in the other is
  # merely a rejected client. This module pins the direction:
  #
  #   THE INVARIANT - every URI the matcher ACCEPTS must resolve, under the
  #   parser a browser actually uses, to a loopback host. If any accepted URI
  #   resolved elsewhere, the authorization server would be handing an
  #   authorization code to a non-loopback origin: an open redirect.
  #
  # The converse is deliberately NOT asserted. Several spellings a browser
  # treats as loopback (`0177.0.0.1`, `2130706433`, `127.1`, a trailing dot,
  # the expanded IPv6 form) are refused by the matcher, which is the safe
  # direction - they simply fall back to exact comparison and must be
  # registered byte-for-byte.
  #
  # Node is the reference here rather than a client library on purpose. An
  # OAuth client library only ever emits `http://127.0.0.1:<port>/cb`, a string
  # this test can construct itself; what cannot be constructed is an
  # independent implementation of the parser that decides where that string
  # points. Driven through `Attesto.Test.NodeBridge`.

  use ExUnit.Case, async: false

  alias Attesto.RedirectURI
  alias Attesto.Test.NodeBridge

  @moduletag :parity

  case NodeBridge.availability() do
    :ok ->
      @moduletag node_ready: true

    {:skip, reason} ->
      @moduletag node_ready: false
      @moduletag skip: "Node parity unavailable: #{reason}"
  end

  # The hosts RFC 8252 §7.3 sanctions, as WHATWG spells them. `[::1]` is
  # reported bracketed by `URL.hostname`.
  @loopback_hosts ["127.0.0.1", "[::1]"]

  # What a native app would plausibly register: the loopback callback in both
  # address families, port `0` by convention (§7.3 ignores it).
  @registered ["http://127.0.0.1:0/cb", "http://[::1]:0/cb"]

  # Legitimate loopback requests, adversarial near-misses, and the encodings an
  # attacker would reach for to smuggle a non-loopback host past a matcher.
  @corpus [
    # Genuine ephemeral-port loopback callbacks.
    "http://127.0.0.1:51823/cb",
    "http://[::1]:51823/cb",
    "http://127.0.0.1/cb",
    "http://127.0.0.1:1/cb",
    "http://127.0.0.1:65535/cb",
    # Userinfo splicing: the loopback literal appears, but the AUTHORITY is not
    # loopback. `URI.parse/1` and WHATWG can disagree about which part is which.
    "http://127.0.0.1@evil.example/cb",
    "http://127.0.0.1:51823@evil.example/cb",
    "http://evil.example@127.0.0.1:51823/cb",
    "http://127.0.0.1\\@evil.example/cb",
    "http://127.0.0.1\t@evil.example/cb",
    "http://127.0.0.1\n@evil.example/cb",
    # Alternative spellings of the loopback address a browser still resolves to
    # 127.0.0.1.
    "http://0177.0.0.1:51823/cb",
    "http://2130706433:51823/cb",
    "http://127.1:51823/cb",
    "http://127.0.0.1.:51823/cb",
    "http://[0:0:0:0:0:0:0:1]:51823/cb",
    "http://[::ffff:127.0.0.1]:51823/cb",
    "http://[::1%25eth0]:51823/cb",
    # The hostname §8.3 rules out.
    "http://localhost:51823/cb",
    "http://LOCALHOST:51823/cb",
    # Port edge cases.
    "http://127.0.0.1:/cb",
    "http://127.0.0.1:0/cb",
    "http://127.0.0.1:65536/cb",
    "http://127.0.0.1:0080/cb",
    "http://127.0.0.1:99999999999/cb",
    # Scheme variants outside the exception.
    "HTTP://127.0.0.1:51823/cb",
    "https://127.0.0.1:51823/cb",
    # Components that must still compare exactly.
    "http://127.0.0.1:51823/cb#f",
    "http://127.0.0.1:51823/cb?a=1",
    "http://127.0.0.1:51823/other",
    # Plainly remote.
    "https://evil.example/cb",
    "http://evil.example:51823/cb"
  ]

  defp whatwg(uri), do: NodeBridge.call!("attesto_compat", :whatwgUrl, [uri])

  defp accepted?(uri, matching), do: RedirectURI.registered?(uri, @registered, matching)

  describe "the accept-set never escapes loopback (RFC 8252 §7.3)" do
    test "every URI the loopback rule accepts resolves to a loopback host in a browser" do
      offenders =
        for uri <- @corpus, accepted?(uri, :exact_allow_loopback_port) do
          parsed = whatwg(uri)

          cond do
            parsed["ok"] != true ->
              {uri, "WHATWG refuses to parse it, so it names no reachable target"}

            parsed["hostname"] not in @loopback_hosts ->
              {uri, "browser resolves host to #{inspect(parsed["hostname"])}"}

            parsed["protocol"] != "http:" ->
              {uri, "browser resolves scheme to #{inspect(parsed["protocol"])}"}

            true ->
              nil
          end
        end
        |> Enum.reject(&is_nil/1)

      assert offenders == [],
             "accepted redirect URIs that a browser would not send to loopback:\n" <>
               Enum.map_join(offenders, "\n", fn {uri, why} -> "  #{inspect(uri)} - #{why}" end)
    end

    test "the same invariant holds under the default exact mode" do
      offenders =
        for uri <- @corpus, accepted?(uri, :exact) do
          parsed = whatwg(uri)
          if parsed["ok"] != true or parsed["hostname"] not in @loopback_hosts, do: uri
        end
        |> Enum.reject(&is_nil/1)

      assert offenders == []
    end

    test "the corpus actually exercises the rule (guards against a vacuous pass)" do
      # If the matcher were replaced by `fn _, _, _ -> false end` the invariant
      # tests above would pass trivially. Pin that some URIs really are
      # accepted, and that the loopback rule accepts strictly more than exact.
      loopback = Enum.filter(@corpus, &accepted?(&1, :exact_allow_loopback_port))
      exact = Enum.filter(@corpus, &accepted?(&1, :exact))

      assert "http://127.0.0.1:51823/cb" in loopback
      assert "http://[::1]:51823/cb" in loopback
      refute "http://127.0.0.1:51823/cb" in exact
      assert length(loopback) > length(exact)
    end
  end

  describe "known parser disagreements are in the safe direction" do
    # RFC 3986 has no special meaning for `\`, so `URI.parse/1` reads
    # `127.0.0.1\` as userinfo and `evil.example` as the host. WHATWG
    # terminates the authority at the backslash, making the host `127.0.0.1`
    # and the remainder path. The two parsers name DIFFERENT hosts for one
    # string - the matcher must not accept it on either reading.
    test "a backslash in the authority is refused despite parsers disagreeing" do
      uri = "http://127.0.0.1\\@evil.example/cb"
      parsed = whatwg(uri)

      assert parsed["hostname"] == "127.0.0.1", "expected WHATWG to read the backslash as a path delimiter"
      assert URI.parse(uri).host == "evil.example", "expected RFC 3986 to read it as userinfo"

      refute accepted?(uri, :exact_allow_loopback_port)
      refute accepted?(uri, :exact)
    end

    test "spellings a browser resolves to loopback are still refused, not accepted" do
      # Refusing these is the conservative direction: they fall back to exact
      # comparison, so a client that wants one must register it verbatim.
      for uri <- [
            "http://0177.0.0.1:51823/cb",
            "http://2130706433:51823/cb",
            "http://127.1:51823/cb",
            "http://127.0.0.1.:51823/cb",
            "http://[0:0:0:0:0:0:0:1]:51823/cb"
          ] do
        assert whatwg(uri)["hostname"] in @loopback_hosts,
               "expected a browser to resolve #{uri} to loopback"

        refute accepted?(uri, :exact_allow_loopback_port),
               "#{uri} must not gain port flexibility from an alternative spelling"
      end
    end

    test "ports the matcher refuses are ones a browser cannot use either" do
      # `:65536` and an overlong port are outright parse errors in WHATWG;
      # `:0` names no connectable endpoint. None may be minted as a target.
      for uri <- ["http://127.0.0.1:65536/cb", "http://127.0.0.1:99999999999/cb"] do
        assert whatwg(uri)["ok"] == false
        refute accepted?(uri, :exact_allow_loopback_port)
      end
    end
  end
end
