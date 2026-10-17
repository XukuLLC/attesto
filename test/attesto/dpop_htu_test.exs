defmodule Attesto.DPoPHtuTest do
  @moduledoc false
  # RFC 9449 §4.3 htu comparison edge cases.
  #
  # `Attesto.DPoP.check_htu/2` compares the effective target URI without
  # query/fragment, normalizes scheme/host case, and treats the default HTTPS
  # port as equivalent to an omitted port. It does not decode path
  # percent-encoding, normalize IPv6 text forms, or accept userinfo-bearing
  # URIs.
  use ExUnit.Case, async: true

  alias Attesto.DPoP
  alias Attesto.Test.Factory

  @http_method "POST"

  # Build verify opts. `:http_uri` is the server-observed (live) URI; the
  # proof's signed `htu` is supplied separately to Factory.dpop_proof.
  defp opts(http_uri, extra) do
    Keyword.merge([http_method: @http_method, http_uri: http_uri], extra)
  end

  # Sign a proof claiming `proof_htu` and verify it against a live request
  # observed at `live_uri`.
  defp verify(proof_htu, live_uri, extra \\ []) do
    {proof, _jkt} = Factory.dpop_proof(htu: proof_htu)
    DPoP.verify_proof(proof, opts(live_uri, extra))
  end

  # -----------------------------------------------------------------
  # baseline: identical strings verify
  # -----------------------------------------------------------------

  describe "exact-match baseline" do
    test "byte-identical htu and live uri verify" do
      uri = "https://api.example.com/resource"
      assert {:ok, result} = verify(uri, uri)
      assert result.htu == uri
    end
  end

  # -----------------------------------------------------------------
  # query and fragment stripping (the one normalization attesto does)
  # -----------------------------------------------------------------

  describe "query and fragment components" do
    test "proof htu with a query is normalized before comparison" do
      assert {:ok, _} =
               verify("https://api.example.com/resource?cb=1", "https://api.example.com/resource")
    end

    test "proof htu with a fragment is normalized before comparison" do
      assert {:ok, _} =
               verify("https://api.example.com/resource#section", "https://api.example.com/resource")
    end

    test "proof htu with both query and fragment is normalized before comparison" do
      assert {:ok, _} =
               verify("https://api.example.com/resource?cb=1&x=2#frag", "https://api.example.com/resource")
    end

    test "query/fragment on the live side are stripped (clean proof still matches)" do
      assert {:ok, _} =
               verify(
                 "https://api.example.com/resource",
                 "https://api.example.com/resource?cursor=abc#top"
               )
    end

    test "a clean proof matches regardless of the live side's query" do
      assert {:ok, _} =
               verify("https://api.example.com/resource", "https://api.example.com/resource?b=2")
    end

    test "a '?' embedded before the path divergence does not hide a path mismatch" do
      # Fragment split happens first, then query split. Here the paths
      # genuinely differ (/a vs /b) so it must reject.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a?x=1",
                 "https://api.example.com/b?x=1"
               )
    end
  end

  # -----------------------------------------------------------------
  # userinfo (https://user:pw@host/x)
  # -----------------------------------------------------------------

  describe "userinfo component" do
    test "userinfo in the proof htu is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://user:pw@api.example.com/resource",
                 "https://api.example.com/resource"
               )
    end

    test "userinfo on both sides is rejected" do
      uri = "https://user:pw@api.example.com/resource"
      assert {:error, :invalid_htu} = verify(uri, uri)
    end

    test "differing userinfo with same host is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://alice@api.example.com/resource",
                 "https://bob@api.example.com/resource"
               )
    end
  end

  # -----------------------------------------------------------------
  # default-port equivalence (host:443 vs host)
  # -----------------------------------------------------------------

  describe "default-port equivalence" do
    test "explicit :443 in proof htu matches a port-less live uri" do
      assert {:ok, _} =
               verify(
                 "https://api.example.com:443/resource",
                 "https://api.example.com/resource"
               )
    end

    test "explicit :443 on both sides verifies" do
      uri = "https://api.example.com:443/resource"
      assert {:ok, _} = verify(uri, uri)
    end

    test "a genuinely different explicit port is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com:8443/resource",
                 "https://api.example.com/resource"
               )
    end
  end

  # -----------------------------------------------------------------
  # host / scheme case (HTTPS://HOST vs https://host)
  # -----------------------------------------------------------------

  describe "scheme and host case" do
    test "uppercase scheme in the proof htu is normalized" do
      assert {:ok, _} =
               verify(
                 "HTTPS://api.example.com/resource",
                 "https://api.example.com/resource"
               )
    end

    test "uppercase scheme in the live uri is normalized" do
      assert {:ok, _} =
               verify(
                 "https://api.example.com/resource",
                 "HTTPS://api.example.com/resource"
               )
    end

    test "lowercase https with differing HOST case is normalized" do
      assert {:ok, _} =
               verify(
                 "https://API.EXAMPLE.COM/resource",
                 "https://api.example.com/resource"
               )
    end

    test "identical host casing on both sides verifies (even if uppercase)" do
      uri = "https://API.EXAMPLE.COM/resource"
      assert {:ok, _} = verify(uri, uri)
    end
  end

  # -----------------------------------------------------------------
  # IPv6 literal host
  # -----------------------------------------------------------------

  describe "IPv6 literal host" do
    test "identical bracketed IPv6 literals verify" do
      uri = "https://[2001:db8::1]/resource"
      assert {:ok, _} = verify(uri, uri)
    end

    test "IPv6 literal with explicit :443 matches the port-less form" do
      assert {:ok, _} =
               verify(
                 "https://[2001:db8::1]:443/resource",
                 "https://[2001:db8::1]/resource"
               )
    end

    test "two textually different but numerically equal IPv6 literals are rejected" do
      # ::1 (compressed) vs 0:0:0:0:0:0:0:1 (expanded) are the same address
      # to an IP-aware comparator. attesto compares text, so they differ.
      assert {:error, :invalid_htu} =
               verify(
                 "https://[::1]/resource",
                 "https://[0:0:0:0:0:0:0:1]/resource"
               )
    end
  end

  # -----------------------------------------------------------------
  # path percent-encoding (%2F vs /)
  # -----------------------------------------------------------------

  describe "path percent-encoding" do
    test "%2F in the proof path does NOT match a literal '/' in the live path" do
      # %2F decodes to '/' but is NOT path-equivalent to a real segment
      # separator per RFC 3986 §2.2 (reserved). A decoding normalizer that
      # naively unescaped would conflate them; attesto compares raw and
      # keeps them distinct. Safe direction.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a%2Fb",
                 "https://api.example.com/a/b"
               )
    end

    test "identical percent-encoding on both sides verifies" do
      uri = "https://api.example.com/a%2Fb"
      assert {:ok, _} = verify(uri, uri)
    end

    test "case difference in a percent-encoding triple is rejected (%2f vs %2F)" do
      # RFC 3986 §6.2.2.1 normalizes percent-encoding hex to uppercase;
      # attesto does not, so %2f and %2F differ.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a%2fb",
                 "https://api.example.com/a%2Fb"
               )
    end

    test "an unencoded reserved char vs its percent form is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/a b",
                 "https://api.example.com/a%20b"
               )
    end
  end

  # -----------------------------------------------------------------
  # trailing slash
  # -----------------------------------------------------------------

  describe "trailing slash" do
    test "trailing slash on the proof side only is rejected" do
      # RFC 3986 treats /resource and /resource/ as distinct paths anyway,
      # so this matches a normalizer: both reject. Asserted for completeness.
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/resource/",
                 "https://api.example.com/resource"
               )
    end

    test "trailing slash on the live side only is rejected" do
      assert {:error, :invalid_htu} =
               verify(
                 "https://api.example.com/resource",
                 "https://api.example.com/resource/"
               )
    end

    test "bare-authority trailing slash and no path are equivalent" do
      # RFC 3986 section 6.2.3 treats an empty authority-based HTTP path as
      # equivalent to "/".
      assert {:ok, _verified} =
               verify(
                 "https://api.example.com/",
                 "https://api.example.com"
               )
    end

    test "trailing slash present on both sides verifies" do
      uri = "https://api.example.com/resource/"
      assert {:ok, _} = verify(uri, uri)
    end
  end
end
