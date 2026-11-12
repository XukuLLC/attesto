defmodule Attesto.Mdoc.Origin do
  @moduledoc false

  # OID4VP 1.0 §2: web origins contain scheme, host and non-default port;
  # native platforms can instead supply an application-specific URI.
  # Validate without normalizing: the platform's exact string is signed.
  def valid?(origin) when is_binary(origin) and origin != "" do
    String.valid?(origin) and not Regex.match?(~r/[\s\\]/u, origin) and valid_uri?(origin)
  end

  def valid?(_origin), do: false

  defp valid_uri?(origin) do
    case URI.new(origin) do
      {:ok, %URI{scheme: scheme} = uri} when scheme in ["http", "https"] ->
        web_origin?(uri, origin)

      {:ok, %URI{scheme: scheme, path: path, host: nil, query: nil, fragment: nil}}
      when is_binary(scheme) and scheme != "origin" and is_binary(path) and path != "" ->
        String.starts_with?(origin, scheme <> ":") and not String.starts_with?(path, "/")

      _other ->
        false
    end
  end

  defp web_origin?(%URI{host: host, path: nil, query: nil, fragment: nil, userinfo: nil, port: port} = uri, origin)
       when is_binary(host) and host != "" and port in 0..65_535 do
    valid_host?(host) and
      URI.to_string(%{uri | authority: nil, host: String.downcase(host)}) == origin
  end

  defp web_origin?(_uri, _origin), do: false

  defp valid_host?(host) do
    if String.contains?(host, ":") do
      match?({:ok, _address}, :inet.parse_ipv6_address(String.to_charlist(host)))
    else
      Regex.match?(~r/\A[a-zA-Z0-9.-]+\z/, host)
    end
  end
end
