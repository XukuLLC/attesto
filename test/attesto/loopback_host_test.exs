defmodule Attesto.LoopbackHostTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.LoopbackHost

  describe "loopback?/1" do
    test "accepts localhost, *.localhost (RFC 6761 §6.3), and is case-insensitive" do
      assert LoopbackHost.loopback?("localhost")
      assert LoopbackHost.loopback?("LOCALHOST")
      assert LoopbackHost.loopback?("app.localhost")
      assert LoopbackHost.loopback?("deep.sub.localhost")
    end

    test "accepts 127.0.0.0/8 dotted-quad literals (RFC 5735 §3)" do
      assert LoopbackHost.loopback?("127.0.0.1")
      assert LoopbackHost.loopback?("127.1.2.3")
    end

    test "accepts the IPv6 loopback, bracketed or bare" do
      assert LoopbackHost.loopback?("::1")
      assert LoopbackHost.loopback?("[::1]")
    end

    test "rejects any host that can name a remote peer" do
      refute LoopbackHost.loopback?("api.example.com")
      refute LoopbackHost.loopback?("localhost.example.com")
      refute LoopbackHost.loopback?("mylocalhost")
      refute LoopbackHost.loopback?("128.0.0.1")
      refute LoopbackHost.loopback?("::2")
    end

    test "rejects non-dotted-quad 127/8 shorthands and non-binary input" do
      # `:inet.parse_address/1` would admit "127.1"; the strict parser does not,
      # so the carve-out stays limited to explicit dotted-quad literals.
      refute LoopbackHost.loopback?("127.1")
      refute LoopbackHost.loopback?(nil)
      refute LoopbackHost.loopback?(:localhost)
    end
  end
end
