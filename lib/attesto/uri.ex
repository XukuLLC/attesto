defmodule Attesto.URI do
  @moduledoc """
  Shared URI validation for protocol identifiers received at trust boundaries.

  The validator rejects userinfo, fragments, hostless identifiers, whitespace,
  control characters, and malformed percent escapes before callers advertise
  or dereference a URL.

  ## Hosts

  A host is refused when it contains a percent-encoded character
  (`auth.example%20evil`) or an empty label (`auth.example..`, `.example`,
  `a..b`). RFC 3986 §3.2.2 allows percent-encoding in a registered name, but a
  DNS name never needs it, and no issuer or endpoint metadata carries one; a
  host that only reads as a name after decoding is not the name it appears to
  be. One trailing dot is kept: `auth.example.` is the fully qualified form of
  `auth.example` and resolves to the same host.

  ## Schemes

  A scheme is case-insensitive (RFC 3986 §3.1). `HTTPS://auth.example` is
  accepted: the scheme is lower-cased when the value is parsed, before it is
  compared.
  """

  @doc """
  Returns whether `value` is an absolute HTTPS identifier.

  Set `:allow_http` to `true` only for a caller that deliberately supports an
  HTTP development endpoint. `allow_loopback_http: true` is the narrower form:
  `http` is accepted only when the host is `localhost` or a literal loopback
  address (`loopback_host?/1`), and `https` is still required for every other
  host. Every other structural check remains active.
  """
  @spec https_identifier?(term(), keyword()) :: boolean()
  def https_identifier?(value, opts \\ [])

  def https_identifier?(value, opts) when is_binary(value) and is_list(opts) do
    allow_http? = Keyword.get(opts, :allow_http, false)
    allow_loopback_http? = Keyword.get(opts, :allow_loopback_http, false)

    is_boolean(allow_http?) and is_boolean(allow_loopback_http?) and value != "" and String.valid?(value) and
      valid_percent_encoding?(value) and
      valid_identifier?(value, http_policy(allow_http?, allow_loopback_http?))
  end

  def https_identifier?(_value, _opts), do: false

  @doc """
  Adds response parameters to a registered redirect URI's query.

  RFC 6749 §3.1.2 requires the registered query component to be retained
  when parameters are added. A registered pair whose name the response sets
  is dropped first, so the client never receives two values for one
  parameter (`?state=static&state=abc123`, where a first-value parser reads
  the registered one). `:replace` names further parameters to drop even when
  this response does not set them, such as `code` on an error response. Every
  other registered pair is kept byte for byte, including repeated and bare
  names and their original percent-encoding. A registered name is compared
  after `application/x-www-form-urlencoded` decoding, so `st%61te` counts as
  `state`.

  `params` is a map or a list of `{name, value}` pairs, encoded with
  `URI.encode_query/1` in the given order.
  """
  @spec put_query_params(String.t(), Enumerable.t(), keyword()) :: String.t()
  def put_query_params(uri, params, opts \\ []) when is_binary(uri) and is_list(opts) do
    params = Enum.to_list(params)
    replaced = MapSet.new(Enum.map(params, fn {name, _value} -> to_string(name) end) ++ Keyword.get(opts, :replace, []))
    parsed = URI.parse(uri)

    kept =
      case parsed.query do
        query when is_binary(query) and query != "" ->
          query |> String.split("&") |> Enum.reject(&(query_pair_name(&1) in replaced))

        _empty ->
          []
      end

    query = Enum.join(kept ++ ([URI.encode_query(params)] -- [""]), "&")
    URI.to_string(%{parsed | query: if(query != "", do: query)})
  end

  defp query_pair_name(pair) do
    raw = pair |> String.split("=", parts: 2) |> hd()

    try do
      URI.decode_www_form(raw)
    rescue
      ArgumentError -> raw
    end
  end

  @doc false
  @spec normalize_path(String.t() | nil) :: String.t()
  def normalize_path(path) when path in [nil, ""], do: "/"
  def normalize_path(path) when is_binary(path), do: path

  @doc false
  @spec valid_port?(String.t(), term()) :: boolean()
  def valid_port?(value, port) when is_binary(value) and is_integer(port) and port in 1..65_535 do
    case Elixir.URI.parse(value).authority do
      authority when is_binary(authority) -> not String.ends_with?(authority, ":")
      _ -> false
    end
  end

  def valid_port?(_value, _port), do: false

  @doc """
  Whether `host` is a usable URI host: non-empty, with no percent-encoded
  character and no empty label. See "Hosts" in the moduledoc.

  An IP literal is accepted as given; IPv6 literals arrive without their
  brackets from `URI.new/1`.
  """
  @spec valid_host?(term()) :: boolean()
  def valid_host?(host) when is_binary(host) and host != "" do
    cond do
      String.contains?(host, "%") -> false
      String.contains?(host, ":") -> true
      true -> host |> strip_root_dot() |> non_empty_labels?()
    end
  end

  def valid_host?(_host), do: false

  # Exactly one trailing dot is the DNS root label; a second one is an empty
  # label and is left in place for the label check to refuse.
  defp strip_root_dot(host) do
    if String.ends_with?(host, "."), do: binary_part(host, 0, byte_size(host) - 1), else: host
  end

  defp non_empty_labels?(name), do: name |> String.split(".") |> Enum.all?(&(&1 != ""))

  @doc """
  Whether `host` names the local machine without a DNS lookup: `localhost`
  (any case, optional trailing dot) or a literal loopback address
  (`127.0.0.0/8`, `::1`).

  A name that merely resolves to a loopback address is not a loopback host;
  resolution is the caller's concern (`Attesto.OutboundTarget`).
  """
  @spec loopback_host?(term()) :: boolean()
  def loopback_host?(host) when is_binary(host) do
    host
    |> String.downcase()
    |> String.trim_trailing(".")
    |> case do
      "localhost" ->
        true

      literal ->
        case :inet.parse_strict_address(String.to_charlist(literal)) do
          {:ok, {127, _b, _c, _d}} -> true
          {:ok, {0, 0, 0, 0, 0, 0, 0, 1}} -> true
          _other -> false
        end
    end
  end

  def loopback_host?(_host), do: false

  defp http_policy(true, _allow_loopback_http?), do: :any
  defp http_policy(false, true), do: :loopback
  defp http_policy(false, false), do: :none

  defp valid_identifier?(value, http_policy) do
    with {:ok, %Elixir.URI{} = uri} <- Elixir.URI.new(value),
         true <- valid_host?(uri.host),
         true <- accepted_scheme?(uri.scheme, http_policy, uri.host),
         true <- is_nil(uri.userinfo),
         true <- is_nil(uri.fragment),
         true <- valid_port?(value, uri.port) do
      true
    else
      _ -> false
    end
  rescue
    _exception -> false
  catch
    _kind, _reason -> false
  end

  defp accepted_scheme?("https", _http_policy, _host), do: true
  defp accepted_scheme?("http", :any, _host), do: true
  defp accepted_scheme?("http", :loopback, host), do: loopback_host?(host)
  defp accepted_scheme?(_scheme, _http_policy, _host), do: false

  defp valid_percent_encoding?(value), do: not Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, value)
end
