defmodule Attesto.LoopbackHost do
  @moduledoc """
  Loopback-host detection backing the development-only plain-`http` carve-outs.

  RFC 8414 §2 (issuer identifiers), RFC 9728 §2 (protected-resource
  identifiers) and RFC 9449 §4.3 (DPoP `htu`) all specify `https` URLs, and
  Attesto enforces that by default. The one deployment where that enforcement
  only hurts is local development on the loopback interface: traffic to
  loopback never leaves the machine, so TLS adds no transport security there -
  the same reasoning RFC 8252 §8.3 uses to exempt loopback redirect URIs from
  the `https` requirement, and the practice MCP tooling expects
  (`http://localhost` development servers).

  A host qualifies as loopback only when it cannot name a remote peer:
  `localhost` and any `*.localhost` name (RFC 6761 §6.3 - resolvers treat
  these as loopback), an IPv4 address in `127.0.0.0/8` (RFC 5735 §3), or the
  IPv6 loopback `::1`. A DNS name that merely *resolves* to loopback does not
  qualify: the string is all this check ever sees, and any other name may
  resolve differently for another party.
  """

  @doc """
  Whether `host` (a `URI` host component) names the loopback interface.

  Accepts the IPv6 loopback both bracketed (`"[::1]"`, as some `URI` parsers
  retain it) and bare (`"::1"`). Any non-binary input is `false`.
  """
  @spec loopback?(term()) :: boolean()
  def loopback?(host) when is_binary(host) do
    case String.downcase(host) do
      "localhost" -> true
      "::1" -> true
      "[::1]" -> true
      down -> String.ends_with?(down, ".localhost") or loopback_ipv4?(down)
    end
  end

  def loopback?(_host), do: false

  # Strict IPv4 parsing so `127.1` / `0177.0.0.1`-style shorthands (which
  # `:inet.parse_address/1` would admit) don't widen the carve-out beyond
  # dotted-quad `127.0.0.0/8` literals.
  defp loopback_ipv4?(host) do
    case :inet.parse_ipv4strict_address(String.to_charlist(host)) do
      {:ok, {127, _, _, _}} -> true
      _ -> false
    end
  end
end
