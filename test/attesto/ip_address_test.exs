defmodule Attesto.IPAddressTest do
  use ExUnit.Case, async: true

  alias Attesto.IPAddress

  describe "public_fetch_destination?/1 for IPv4" do
    test "accepts public destinations and the globally reachable IANA exceptions" do
      for address <- [
            {8, 8, 8, 8},
            {93, 184, 216, 34},
            {192, 0, 0, 9},
            {192, 0, 0, 10},
            {192, 31, 196, 1},
            {192, 52, 193, 1},
            {192, 175, 48, 1}
          ] do
        assert IPAddress.public_fetch_destination?(address), inspect(address)
      end
    end

    test "rejects non-global and special-purpose destinations" do
      for address <- [
            {0, 0, 0, 0},
            {10, 0, 0, 1},
            {100, 64, 0, 1},
            {100, 127, 255, 255},
            {127, 0, 0, 1},
            {169, 254, 169, 254},
            {172, 16, 0, 1},
            {172, 31, 255, 255},
            {192, 0, 0, 0},
            {192, 0, 0, 8},
            {192, 0, 0, 11},
            {192, 0, 0, 170},
            {192, 0, 0, 171},
            {192, 0, 2, 1},
            {192, 88, 99, 1},
            {192, 168, 0, 1},
            {198, 18, 0, 1},
            {198, 19, 255, 255},
            {198, 51, 100, 1},
            {203, 0, 113, 1},
            {224, 0, 0, 1},
            {239, 255, 255, 255},
            {240, 0, 0, 1},
            {255, 255, 255, 255}
          ] do
        refute IPAddress.public_fetch_destination?(address), inspect(address)
      end
    end
  end

  describe "public_fetch_destination?/1 for IPv6" do
    test "accepts ordinary global unicast and globally reachable IANA allocations" do
      for address <- [
            {0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111},
            {0x2001, 0x0001, 0, 0, 0, 0, 0, 1},
            {0x2001, 0x0001, 0, 0, 0, 0, 0, 2},
            {0x2001, 0x0001, 0, 0, 0, 0, 0, 3},
            {0x2001, 0x0003, 0xFFFF, 0, 0, 0, 0, 1},
            {0x2001, 0x0004, 0x0112, 0, 0, 0, 0, 1},
            {0x2001, 0x0200, 0, 0, 0, 0, 0, 1},
            {0x2620, 0x004F, 0x8000, 0, 0, 0, 0, 1}
          ] do
        assert IPAddress.public_fetch_destination?(address), inspect(address)
      end
    end

    test "rejects non-global, scoped, multicast, and reserved destinations" do
      for address <- [
            {0, 0, 0, 0, 0, 0, 0, 0},
            {0, 0, 0, 0, 0, 0, 0, 1},
            {0x0100, 0, 0, 0, 0, 0, 0, 1},
            {0x0100, 0, 0, 1, 0, 0, 0, 1},
            {0x2001, 0, 0, 0, 0, 0, 0, 1},
            {0x2001, 1, 0, 0, 0, 0, 0, 4},
            {0x2001, 2, 0, 0, 0, 0, 0, 1},
            {0x2001, 0x0010, 0, 0, 0, 0, 0, 1},
            {0x2001, 0x0020, 0, 0, 0, 0, 0, 1},
            {0x2001, 0x002F, 0xFFFF, 0, 0, 0, 0, 1},
            {0x2001, 0x0030, 0, 0, 0, 0, 0, 1},
            {0x2001, 0x003F, 0xFFFF, 0, 0, 0, 0, 1},
            {0x2001, 0x0040, 0, 0, 0, 0, 0, 1},
            {0x2001, 0x01FF, 0, 0, 0, 0, 0, 1},
            {0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1},
            {0x3FFF, 0x0FFF, 0, 0, 0, 0, 0, 1},
            {0x4000, 0, 0, 0, 0, 0, 0, 1},
            {0x5F00, 0, 0, 0, 0, 0, 0, 1},
            {0xFC00, 0, 0, 0, 0, 0, 0, 1},
            {0xFDFF, 0, 0, 0, 0, 0, 0, 1},
            {0xFE80, 0, 0, 0, 0, 0, 0, 1},
            {0xFEC0, 0, 0, 0, 0, 0, 0, 1},
            {0xFF00, 0, 0, 0, 0, 0, 0, 1}
          ] do
        refute IPAddress.public_fetch_destination?(address), inspect(address)
      end
    end

    test "checks embedded IPv4 destinations in transition formats" do
      public_ipv4 = {0x5DB8, 0xD822}
      loopback_ipv4 = {0x7F00, 0x0001}
      link_local_ipv4 = {0xA9FE, 0xA9FE}

      for {high, low} <- [public_ipv4] do
        assert IPAddress.public_fetch_destination?({0, 0, 0, 0, 0, 0, high, low})
        assert IPAddress.public_fetch_destination?({0, 0, 0, 0, 0, 0xFFFF, high, low})
        assert IPAddress.public_fetch_destination?({0x0064, 0xFF9B, 0, 0, 0, 0, high, low})
        assert IPAddress.public_fetch_destination?({0x2002, high, low, 0, 0, 0, 0, 0})
      end

      for {high, low} <- [loopback_ipv4, link_local_ipv4] do
        refute IPAddress.public_fetch_destination?({0, 0, 0, 0, 0, 0, high, low})
        refute IPAddress.public_fetch_destination?({0, 0, 0, 0, 0, 0xFFFF, high, low})
        refute IPAddress.public_fetch_destination?({0x0064, 0xFF9B, 0, 0, 0, 0, high, low})
        refute IPAddress.public_fetch_destination?({0x2002, high, low, 0, 0, 0, 0, 0})
      end
    end

    test "rejects the entire local-use NAT64 prefix" do
      for address <- [
            {0x0064, 0xFF9B, 1, 0, 0, 0, 0, 1},
            {0x0064, 0xFF9B, 1, 0x5DB8, 0x00D8, 0x2200, 0, 0},
            {0x0064, 0xFF9B, 1, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}
          ] do
        refute IPAddress.public_fetch_destination?(address), inspect(address)
      end
    end
  end

  test "malformed tuples and components fail closed" do
    for address <- [
          nil,
          :invalid,
          {},
          {8, 8, 8},
          {8, 8, 8, 8, 8},
          {-1, 0, 0, 1},
          {256, 0, 0, 1},
          {1.0, 0, 0, 1},
          {0x1_0000, 0, 0, 0, 0, 0, 0, 1},
          {0x2001, 0, 0, 0, 0, 0, 0, -1},
          {0x2001, 0, 0, 0, 0, 0, 0, :one}
        ] do
      refute IPAddress.public_fetch_destination?(address), inspect(address)
    end
  end

  describe "parse_cidrs!/1 and in_any_cidr?/2" do
    test "matches addresses inside the listed blocks only" do
      cidrs = IPAddress.parse_cidrs!(["10.20.0.0/16", "192.168.7.4/32", "fd12:3456::/32"])

      for inside <- [{10, 20, 0, 1}, {10, 20, 255, 255}, {192, 168, 7, 4}, {0xFD12, 0x3456, 0, 0, 0, 0, 0, 9}] do
        assert IPAddress.in_any_cidr?(inside, cidrs), inspect(inside)
      end

      for outside <- [
            {10, 21, 0, 1},
            {10, 19, 255, 255},
            {192, 168, 7, 5},
            {0xFD12, 0x3457, 0, 0, 0, 0, 0, 9},
            {127, 0, 0, 1},
            {169, 254, 169, 254},
            :not_an_address
          ] do
        refute IPAddress.in_any_cidr?(outside, cidrs), inspect(outside)
      end

      refute IPAddress.in_any_cidr?({10, 20, 0, 1}, [])
    end

    test "an IPv4-mapped IPv6 address matches its IPv4 block, and families do not cross" do
      v4 = IPAddress.parse_cidrs!(["10.20.0.0/16"])
      assert IPAddress.in_any_cidr?({0, 0, 0, 0, 0, 0xFFFF, 0x0A14, 0x0001}, v4)
      refute IPAddress.in_any_cidr?({0, 0, 0, 0, 0, 0xFFFF, 0x0A15, 0x0001}, v4)
      refute IPAddress.in_any_cidr?({0x0A14, 0, 0, 0, 0, 0, 0, 1}, v4)
    end

    test "refuses malformed blocks, host bits, and catch-all prefixes" do
      for invalid <- [
            "10.20.0.0",
            "10.20.0.0/",
            "10.20.0.0/33",
            "10.20.0.0/-1",
            "10.20.0.0/16/1",
            "10.20.0.0/016",
            "10.20.0.0/16 ",
            "10.20.0.1/16",
            "fd12:3456::1/32",
            "0.0.0.0/0",
            "::/0",
            "internal.example/16",
            "10.20.0.0/sixteen",
            "",
            nil,
            {10, 20, 0, 0}
          ] do
        assert_raise ArgumentError, ~r/invalid CIDR/, fn -> IPAddress.parse_cidrs!([invalid]) end
      end

      assert_raise ArgumentError, ~r/must be a list/, fn -> IPAddress.parse_cidrs!("10.20.0.0/16") end
      assert IPAddress.parse_cidrs!([]) == []
    end
  end
end
