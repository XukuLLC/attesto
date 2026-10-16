defmodule Attesto.IPAddress do
  @moduledoc """
  Address policy for outbound server-side fetches.

  `public_fetch_destination?/1` accepts valid IP tuples that are suitable for
  fetching an Internet resource and fails closed for malformed input. The
  policy follows the IANA IPv4 and IPv6 Special-Purpose Address Registries:
  non-global, scoped, multicast, documentation, benchmarking, and reserved
  destinations are refused, while the registries' more-specific globally
  reachable allocations remain usable.

  IPv4-compatible, IPv4-mapped, NAT64, and 6to4 forms are checked against the
  embedded IPv4 destination so an alternate representation cannot bypass the
  IPv4 policy.

  See:

    * https://www.iana.org/assignments/iana-ipv4-special-registry/
    * https://www.iana.org/assignments/iana-ipv6-special-registry/
  """

  @type ip_address :: :inet.ip_address()

  @doc """
  Returns whether an IP tuple is a public destination for a server-side fetch.

  Invalid tuple sizes, non-integer components, and out-of-range components are
  rejected. Hostname resolution and DNS-rebinding protection remain the
  caller's responsibility.
  """
  @spec public_fetch_destination?(term()) :: boolean()
  def public_fetch_destination?({a, b, c, d} = address) do
    valid_components?([a, b, c, d], 0xFF) and public_ipv4?(address)
  end

  def public_fetch_destination?({a, b, c, d, e, f, g, h} = address) do
    valid_components?([a, b, c, d, e, f, g, h], 0xFFFF) and public_ipv6?(address)
  end

  def public_fetch_destination?(_address), do: false

  # IANA carves two globally reachable anycast addresses out of the otherwise
  # non-global 192.0.0.0/24 protocol-assignment block.
  defp public_ipv4?({192, 0, 0, last}) when last in [9, 10], do: true

  defp public_ipv4?({0, _, _, _}), do: false
  defp public_ipv4?({10, _, _, _}), do: false
  defp public_ipv4?({100, second, _, _}) when second in 64..127, do: false
  defp public_ipv4?({127, _, _, _}), do: false
  defp public_ipv4?({169, 254, _, _}), do: false
  defp public_ipv4?({172, second, _, _}) when second in 16..31, do: false
  defp public_ipv4?({192, 0, 0, _}), do: false
  defp public_ipv4?({192, 0, 2, _}), do: false
  defp public_ipv4?({192, 88, 99, _}), do: false
  defp public_ipv4?({192, 168, _, _}), do: false
  defp public_ipv4?({198, second, _, _}) when second in 18..19, do: false
  defp public_ipv4?({198, 51, 100, _}), do: false
  defp public_ipv4?({203, 0, 113, _}), do: false
  defp public_ipv4?({first, _, _, _}) when first in 224..255, do: false
  defp public_ipv4?({_a, _b, _c, _d}), do: true

  # Deprecated IPv4-compatible IPv6 (::a.b.c.d).
  defp public_ipv6?({0, 0, 0, 0, 0, 0, high, low}), do: public_ipv4?(embedded_ipv4(high, low))

  # IPv4-mapped IPv6 (::ffff:a.b.c.d).
  defp public_ipv6?({0, 0, 0, 0, 0, 0xFFFF, high, low}), do: public_ipv4?(embedded_ipv4(high, low))

  # The well-known NAT64 prefix is globally reachable. Apply the IPv4 policy
  # to its embedded destination.
  defp public_ipv6?({0x0064, 0xFF9B, 0, 0, 0, 0, high, low}), do: public_ipv4?(embedded_ipv4(high, low))

  # The RFC 8215 local-use NAT64 prefix permits multiple embedding layouts, so
  # reject the entire prefix rather than attempting to decode one layout.
  defp public_ipv6?({0x0064, 0xFF9B, 0x0001, _, _, _, _, _}), do: false

  # 6to4 carries its IPv4 destination in words two and three.
  defp public_ipv6?({0x2002, high, low, _, _, _, _, _}), do: public_ipv4?(embedded_ipv4(high, low))

  # Discard-only and dummy prefixes.
  defp public_ipv6?({0x0100, 0, 0, 0, _, _, _, _}), do: false
  defp public_ipv6?({0x0100, 0, 0, 1, _, _, _, _}), do: false

  # More-specific globally reachable allocations inside the otherwise
  # non-global 2001::/23 IETF protocol-assignment block.
  defp public_ipv6?({0x2001, 0x0001, 0, 0, 0, 0, 0, last}) when last in 1..3, do: true
  defp public_ipv6?({0x2001, 0x0003, _, _, _, _, _, _}), do: true
  defp public_ipv6?({0x2001, 0x0004, 0x0112, _, _, _, _, _}), do: true
  # ORCHIDv2 and Drone Remote ID Protocol Entity Tags are non-locator
  # identifiers. Keep them out of an outbound-fetch allowlist even though the
  # IANA registry marks their allocations globally reachable.
  defp public_ipv6?({0x2001, second, _, _, _, _, _, _}) when second in 0x0020..0x003F, do: false
  defp public_ipv6?({0x2001, second, _, _, _, _, _, _}) when second <= 0x01FF, do: false

  defp public_ipv6?({0x2001, 0x0DB8, _, _, _, _, _, _}), do: false
  defp public_ipv6?({0x3FFF, second, _, _, _, _, _, _}) when second <= 0x0FFF, do: false
  defp public_ipv6?({0x5F00, _, _, _, _, _, _, _}), do: false

  # IANA currently allocates global unicast from 2000::/3. Special-purpose
  # exclusions above take precedence; everything outside it remains refused
  # unless an earlier transition-mechanism clause reduced it to public IPv4.
  defp public_ipv6?({first, _, _, _, _, _, _, _}) when first in 0x2000..0x3FFF, do: true
  defp public_ipv6?({_a, _b, _c, _d, _e, _f, _g, _h}), do: false

  defp embedded_ipv4(high, low), do: {div(high, 0x100), rem(high, 0x100), div(low, 0x100), rem(low, 0x100)}

  defp valid_components?(components, maximum) do
    Enum.all?(components, &(is_integer(&1) and &1 >= 0 and &1 <= maximum))
  end
end
