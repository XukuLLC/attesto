defmodule Attesto.URITest do
  use ExUnit.Case, async: true

  alias Attesto.URI, as: AttestoURI

  test "accepts absolute HTTPS identifiers" do
    assert AttestoURI.https_identifier?("https://resource.example/path?x=1")
    assert AttestoURI.https_identifier?("https://[2001:db8::1]:8443/path")
    assert AttestoURI.https_identifier?("https://resource.example/%2e%2e")
  end

  test "HTTP requires an explicit opt-in" do
    refute AttestoURI.https_identifier?("http://127.0.0.1:4000/resource")
    assert AttestoURI.https_identifier?("http://127.0.0.1:4000/resource", allow_http: true)
  end

  test "rejects authority and encoding hazards" do
    for value <- [
          "https://user:password@resource.example/path",
          "https://resource.example/path#fragment",
          "https://:///path",
          "https:///path",
          "https://resource.example:0/path",
          "https://resource.example:65536/path",
          "https://resource.example:99999/path",
          "https://resource.example:/path",
          "https://resource.example:",
          "https://[2001:db8::1]:/path",
          "https://resource.example/%ZZ",
          "https://resource.example/%2",
          "https://resource.example/a b",
          "https://resource.example/\x01",
          <<255>>,
          "/relative",
          "",
          nil
        ] do
      refute AttestoURI.https_identifier?(value)
    end
  end

  test "invalid options fail closed" do
    refute AttestoURI.https_identifier?("https://resource.example", allow_http: :yes)
    refute AttestoURI.https_identifier?("https://resource.example", %{allow_http: true})
  end

  describe "hosts" do
    test "a percent-encoded character in the host is refused" do
      for value <- [
            "https://auth.test%20evil/",
            "https://auth%2Etest/",
            "https://b%61d.example/",
            "https://[fe80::1%25eth0]/"
          ] do
        refute AttestoURI.https_identifier?(value), value
      end

      # Percent-encoding elsewhere in the URL is untouched.
      assert AttestoURI.https_identifier?("https://auth.test/a%20b?x=%2F")
    end

    test "an empty label is refused, and one trailing dot is the fully qualified form" do
      for value <- ["https://auth.test../", "https://.auth.test/", "https://auth..test/", "https://./", "https://../"] do
        refute AttestoURI.https_identifier?(value), value
      end

      assert AttestoURI.https_identifier?("https://auth.test./")
      assert AttestoURI.https_identifier?("https://localhost/")
    end

    test "valid_host?/1 applies the same rule to a bare host" do
      assert AttestoURI.valid_host?("auth.test")
      assert AttestoURI.valid_host?("auth.test.")
      assert AttestoURI.valid_host?("2001:db8::1")
      assert AttestoURI.valid_host?("192.0.2.1")

      for host <- ["", ".", "auth.test..", "a..b", ".a", "a%2eb", nil, 1] do
        refute AttestoURI.valid_host?(host), inspect(host)
      end
    end
  end

  describe "schemes" do
    test "an upper-case scheme is accepted and compared in lower case (RFC 3986 §3.1)" do
      assert AttestoURI.https_identifier?("HTTPS://auth.test/")
      assert AttestoURI.https_identifier?("Https://auth.test/")
      refute AttestoURI.https_identifier?("HTTP://auth.test/")
      assert AttestoURI.https_identifier?("HTTP://auth.test/", allow_http: true)
    end
  end

  describe "allow_loopback_http" do
    test "http is accepted only for localhost and literal loopback addresses" do
      for value <- [
            "http://localhost:4000/",
            "http://LOCALHOST/",
            "http://localhost./",
            "http://127.0.0.1:4000/",
            "http://127.9.9.9/",
            "http://[::1]:4000/"
          ] do
        assert AttestoURI.https_identifier?(value, allow_loopback_http: true), value
        refute AttestoURI.https_identifier?(value), value
      end

      for value <- [
            "http://auth.test/",
            "http://localhost.evil.test/",
            "http://127.0.0.1.evil.test/",
            "http://10.0.0.1/",
            "http://[::2]/",
            "http://0.0.0.0/",
            "http://2130706433/"
          ] do
        refute AttestoURI.https_identifier?(value, allow_loopback_http: true), value
      end

      assert AttestoURI.https_identifier?("https://auth.test/", allow_loopback_http: true)
      refute AttestoURI.https_identifier?("http://localhost/", allow_loopback_http: :yes)
    end

    test "loopback_host?/1 does no lookup" do
      assert AttestoURI.loopback_host?("localhost")
      assert AttestoURI.loopback_host?("127.0.0.1")
      assert AttestoURI.loopback_host?("::1")
      refute AttestoURI.loopback_host?("local.test")
      refute AttestoURI.loopback_host?("::ffff:127.0.0.1")
      refute AttestoURI.loopback_host?(nil)
    end
  end
end
