defmodule Attesto.OutboundTarget do
  @moduledoc """
  Screen an outbound server-to-server URL against SSRF and pin the target to a
  checked IP address.

  `screen/2` validates that the URL uses `https` (or `http` only when
  `allow_loopback: true`), resolves both `A` (`:inet`) and `AAAA` (`:inet6`)
  records via `:resolver` (default `:inet.getaddrs/2`), checks every returned
  address against `Attesto.IPAddress.public_fetch_destination?/1`, and returns
  the URL rewritten to dial the first checked IP alongside the original `host`
  and `authority`.

  Callers connect to the pinned IP while keeping TLS SNI, certificate-hostname
  verification, and the HTTP `Host` header on the original name, closing the
  DNS-rebinding TOCTOU window between resolution and connection.
  """

  alias Attesto.IPAddress

  @typedoc """
  A screened outbound target:

    * `:url` - the URL with its host rewritten to the checked IP address.
    * `:host` - the original bare hostname for TLS SNI and certificate checks.
    * `:authority` - the original `host[:port]` (with IPv6 bracketed) for the
      HTTP `Host` header.
  """
  @type screened :: %{
          url: String.t(),
          host: String.t(),
          authority: String.t()
        }

  @type error_reason ::
          :invalid_url
          | :insecure_or_hostless_url
          | :invalid_resolver
          | :unresolvable
          | {:blocked_ip, IPAddress.ip_address()}

  @doc """
  Screen `url` and return a pinned target map `{:ok, %{url, host, authority}}`
  or `{:error, reason}`.

  Options:

    * `:resolver` - a
      `(charlist(), :inet | :inet6 -> {:ok, [:inet.ip_address()]} | {:error, term()})`
      function (defaults to `&:inet.getaddrs/2`).
    * `:allow_loopback` - development/test escape hatch (default `false`). When
      `true`, loopback addresses (`127.0.0.0/8`, `::1`, and IPv4-mapped
      `::ffff:127.0.0.0/8`) are permitted and `http` is accepted. Every other
      special-use range remains blocked.
  """
  @spec screen(String.t(), keyword()) :: {:ok, screened()} | {:error, error_reason()}
  def screen(url, opts \\ [])

  def screen(url, opts) when is_binary(url) and is_list(opts) do
    allow_loopback = allow_loopback!(opts)

    with {:ok, uri} <- validate_url(url, allow_loopback),
         {:ok, resolver} <- resolve_resolver(opts),
         {:ok, ips} <- resolve_addrs(uri.host, resolver),
         {:ok, pinned} <- pin(ips, allow_loopback) do
      {:ok,
       %{
         url: URI.to_string(%{uri | host: ip_to_string(pinned)}),
         host: uri.host,
         authority: authority(uri)
       }}
    end
  end

  def screen(_url, _opts), do: {:error, :invalid_url}

  @doc false
  @spec authority(URI.t()) :: String.t()
  def authority(%URI{host: host, port: port, scheme: scheme}) when is_binary(host) and is_integer(port) do
    host_part = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host

    if default_port?(scheme, port),
      do: host_part,
      else: host_part <> ":" <> Integer.to_string(port)
  end

  defp allow_loopback!(opts) do
    case Keyword.get(opts, :allow_loopback, false) do
      value when is_boolean(value) ->
        value

      _unexpected ->
        raise ArgumentError, ":allow_loopback must be true or false"
    end
  end

  defp validate_url(url, allow_loopback) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host, userinfo: nil, fragment: nil} = uri}
      when is_binary(host) and host != "" and
             (scheme == "https" or (allow_loopback and scheme == "http")) ->
        if valid_percent_encoding?(url), do: {:ok, uri}, else: {:error, :invalid_url}

      {:ok, _uri} ->
        {:error, :insecure_or_hostless_url}

      {:error, _reason} ->
        {:error, :invalid_url}
    end
  end

  defp valid_percent_encoding?(value), do: not Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, value)

  defp resolve_resolver(opts) do
    case Keyword.fetch(opts, :resolver) do
      :error -> {:ok, &:inet.getaddrs/2}
      {:ok, nil} -> {:ok, &:inet.getaddrs/2}
      {:ok, resolver} when is_function(resolver, 2) -> {:ok, resolver}
      {:ok, _invalid} -> {:error, :invalid_resolver}
    end
  end

  # Resolve both A and AAAA; every returned address is screened so a mixed
  # answer cannot smuggle an internal address in via the unused family.
  defp resolve_addrs(host, resolver) do
    host_charlist = String.to_charlist(host)

    case lookup(resolver, host_charlist, :inet) ++ lookup(resolver, host_charlist, :inet6) do
      [] -> {:error, :unresolvable}
      ips -> {:ok, ips}
    end
  end

  defp lookup(resolver, host_charlist, family) do
    case resolver.(host_charlist, family) do
      {:ok, ips} when is_list(ips) -> ips
      _other -> []
    end
  end

  defp pin(ips, allow_loopback) do
    case Enum.find(ips, &blocked_ip?(&1, allow_loopback)) do
      nil -> {:ok, hd(ips)}
      blocked -> {:error, {:blocked_ip, blocked}}
    end
  end

  defp blocked_ip?(ip, true), do: not loopback?(ip) and not IPAddress.public_fetch_destination?(ip)
  defp blocked_ip?(ip, false), do: not IPAddress.public_fetch_destination?(ip)

  defp loopback?({127, _b, _c, _d}), do: true
  defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp loopback?({0, 0, 0, 0, 0, 0xFFFF, w7, _w8}) when div(w7, 256) == 127, do: true
  defp loopback?(_ip), do: false

  defp default_port?("https", 443), do: true
  defp default_port?("http", 80), do: true
  defp default_port?(_scheme, _port), do: false

  defp ip_to_string(ip), do: ip |> :inet.ntoa() |> to_string()
end
