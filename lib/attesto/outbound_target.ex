defmodule Attesto.OutboundTarget do
  @moduledoc """
  Screen an outbound server-to-server URL against SSRF and pin the target to a
  checked IP address.

  `screen/2` validates that the URL uses `https` (or `http` only when
  `allow_loopback: true`, and then only to loopback addresses), resolves both `A` (`:inet`) and
  `AAAA` (`:inet6`) records via `:resolver` (default `:inet.getaddrs/2`),
  checks every returned address against
  `Attesto.IPAddress.public_fetch_destination?/1`, and returns the URL
  rewritten to dial the first checked IP alongside the original `host` and
  `authority`.

  ## Exceptions an operator takes on

  Both options below open the screen on purpose. Each is exact: there is no
  "allow private addresses" switch.

    * `:allowed_cidrs` names the non-public networks a destination may
      resolve into, for a service that is only reachable at a private address
      (a cluster-internal name, split-horizon DNS). It is a list of CIDR
      blocks and nothing else. A host name is not accepted as an allowance,
      because that would trust DNS: whoever controls the name's answer could
      point it at any private address. With a block, the answer is still
      checked, and an address outside every listed block is refused.
    * `:allow_loopback` is for development against a server on the local
      machine.

  The screen applies to the one URL it is given. A caller that follows
  redirects screens every hop with the same options, so a redirect to an
  address outside the allowance is refused like any other.

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
      `::ffff:127.0.0.0/8`) are permitted. `http` is accepted only when every
      address the host resolves to is a loopback address; a destination
      anywhere else still needs `https`. Every other special-use range
      remains blocked. A caller that wants to accept `http` only for
      `localhost` and literal loopback addresses, without a lookup, checks
      the URL with `Attesto.URI.https_identifier?/2` and
      `allow_loopback_http: true` first.
    * `:allowed_cidrs` - a list of CIDR strings (default `[]`) naming
      non-public networks a destination may resolve into, such as
      `["10.20.0.0/16", "fd12:3456::/32"]`. Every resolved address must be a
      public destination or fall inside one of the blocks. Validated by
      `Attesto.IPAddress.parse_cidrs!/1`, which raises `ArgumentError` for a
      malformed block, a block with host bits set, or a zero-length prefix.
      This is an SSRF exception: list only networks whose every host the
      caller is willing to send this request to.
  """
  @spec screen(String.t(), keyword()) :: {:ok, screened()} | {:error, error_reason()}
  def screen(url, opts \\ [])

  def screen(url, opts) when is_binary(url) and is_list(opts) do
    allow_loopback = allow_loopback!(opts)
    allowed_cidrs = opts |> Keyword.get(:allowed_cidrs, []) |> IPAddress.parse_cidrs!()

    with {:ok, uri} <- validate_url(url, allow_loopback),
         {:ok, resolver} <- resolve_resolver(opts),
         {:ok, ips} <- resolve_addrs(uri.host, resolver),
         {:ok, pinned} <- pin(ips, uri.scheme, allow_loopback, allowed_cidrs) do
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
      {:ok, %URI{userinfo: nil, fragment: nil} = uri} -> validate_parsed_url(url, uri, allow_loopback)
      {:ok, _uri} -> {:error, :insecure_or_hostless_url}
      {:error, _reason} -> {:error, :invalid_url}
    end
  end

  defp validate_parsed_url(url, %URI{scheme: scheme, host: host} = uri, allow_loopback)
       when is_binary(host) and host != "" and scheme in ["https", "http"] do
    cond do
      not valid_percent_encoding?(url) -> {:error, :invalid_url}
      not Attesto.URI.valid_host?(host) -> {:error, :invalid_url}
      scheme == "https" or allow_loopback -> {:ok, uri}
      true -> {:error, :insecure_or_hostless_url}
    end
  end

  defp validate_parsed_url(_url, _uri, _allow_loopback), do: {:error, :insecure_or_hostless_url}

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

  defp pin(ips, scheme, allow_loopback, allowed_cidrs) do
    case Enum.find(ips, &blocked_ip?(&1, scheme, allow_loopback, allowed_cidrs)) do
      nil -> {:ok, hd(ips)}
      blocked -> {:error, {:blocked_ip, blocked}}
    end
  end

  # Plain `http` is only ever sent to the local machine. `allow_loopback`
  # admits the scheme, and here every address the host resolved to has to be a
  # loopback address, so the flag cannot carry a request to a remote host in
  # the clear, and an allowed CIDR never applies to `http`.
  defp blocked_ip?(ip, "http", _allow_loopback, _allowed_cidrs), do: not loopback?(ip)

  defp blocked_ip?(ip, _https, allow_loopback, allowed_cidrs) do
    not (IPAddress.public_fetch_destination?(ip) or (allow_loopback and loopback?(ip)) or
           IPAddress.in_any_cidr?(ip, allowed_cidrs))
  end

  defp loopback?({127, _b, _c, _d}), do: true
  defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp loopback?({0, 0, 0, 0, 0, 0xFFFF, w7, _w8}) when div(w7, 256) == 127, do: true
  defp loopback?(_ip), do: false

  defp default_port?("https", 443), do: true
  defp default_port?("http", 80), do: true
  defp default_port?(_scheme, _port), do: false

  defp ip_to_string(ip), do: ip |> :inet.ntoa() |> to_string()
end
