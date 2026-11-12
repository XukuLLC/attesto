defmodule Attesto.OutboundTargetTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.OutboundTarget

  defp resolver(v4, v6 \\ []) do
    fn _host, family ->
      case family do
        :inet -> {:ok, v4}
        :inet6 -> {:ok, v6}
      end
    end
  end

  describe "allowed_cidrs" do
    test "a destination inside a listed block is pinned, and one outside stays refused" do
      opts = [allowed_cidrs: ["10.20.0.0/16", "fd12:3456::/32"]]

      assert {:ok, %{url: "https://10.20.3.4/token", host: "idp.internal", authority: "idp.internal"}} =
               OutboundTarget.screen("https://idp.internal/token", [resolver: resolver([{10, 20, 3, 4}])] ++ opts)

      assert {:ok, %{host: "idp.internal"}} =
               OutboundTarget.screen(
                 "https://idp.internal/token",
                 [resolver: resolver([], [{0xFD12, 0x3456, 0, 0, 0, 0, 0, 7}])] ++ opts
               )

      for blocked <- [{10, 21, 3, 4}, {192, 168, 1, 1}, {169, 254, 169, 254}, {127, 0, 0, 1}] do
        assert {:error, {:blocked_ip, ^blocked}} =
                 OutboundTarget.screen("https://idp.internal/token", [resolver: resolver([blocked])] ++ opts)
      end
    end

    test "every resolved address must pass: one outside the list refuses the target" do
      assert {:error, {:blocked_ip, {192, 168, 1, 1}}} =
               OutboundTarget.screen("https://idp.internal/token",
                 resolver: resolver([{10, 20, 3, 4}, {192, 168, 1, 1}]),
                 allowed_cidrs: ["10.20.0.0/16"]
               )
    end

    test "a public destination needs no listing, and the default list allows nothing private" do
      assert {:ok, _target} =
               OutboundTarget.screen("https://rp.example/x",
                 resolver: resolver([{93, 184, 216, 34}]),
                 allowed_cidrs: ["10.20.0.0/16"]
               )

      assert {:error, {:blocked_ip, {10, 20, 3, 4}}} =
               OutboundTarget.screen("https://idp.internal/token", resolver: resolver([{10, 20, 3, 4}]))
    end

    test "the list is validated before anything is resolved" do
      for invalid <- [["10.20.0.0"], ["0.0.0.0/0"], ["10.20.0.1/16"], "10.20.0.0/16", [:private]] do
        assert_raise ArgumentError, fn ->
          OutboundTarget.screen("https://idp.internal/token",
            resolver: fn _host, _family -> flunk("resolved before validating :allowed_cidrs") end,
            allowed_cidrs: invalid
          )
        end
      end
    end

    test "an allowed block never carries plain http" do
      assert {:error, :insecure_or_hostless_url} =
               OutboundTarget.screen("http://idp.internal/token",
                 resolver: resolver([{10, 20, 3, 4}]),
                 allowed_cidrs: ["10.20.0.0/16"]
               )

      assert {:error, {:blocked_ip, {10, 20, 3, 4}}} =
               OutboundTarget.screen("http://idp.internal/token",
                 resolver: resolver([{10, 20, 3, 4}]),
                 allowed_cidrs: ["10.20.0.0/16"],
                 allow_loopback: true
               )
    end
  end

  describe "allow_loopback and http" do
    test "http reaches loopback addresses only" do
      assert {:ok, %{url: "http://127.0.0.1:4000/cb"}} =
               OutboundTarget.screen("http://localhost:4000/cb",
                 resolver: resolver([{127, 0, 0, 1}]),
                 allow_loopback: true
               )

      # Before this rule, the development flag let plain http reach a public
      # address.
      assert {:error, {:blocked_ip, {93, 184, 216, 34}}} =
               OutboundTarget.screen("http://rp.example/cb",
                 resolver: resolver([{93, 184, 216, 34}]),
                 allow_loopback: true
               )

      assert {:error, {:blocked_ip, {93, 184, 216, 34}}} =
               OutboundTarget.screen("http://localhost/cb",
                 resolver: resolver([{127, 0, 0, 1}, {93, 184, 216, 34}]),
                 allow_loopback: true
               )
    end

    test "a host with a percent-encoded character or an empty label is not a URL to dial" do
      for url <- ["https://rp.example%20evil/x", "https://rp.example../x"] do
        assert {:error, :invalid_url} = OutboundTarget.screen(url, resolver: resolver([{93, 184, 216, 34}]))
      end
    end
  end

  describe "differential parity with SSRFGuard and Discovery.screen_endpoint" do
    test "produces identical targets and verdicts across URLs, resolvers, IPv4-mapped IPv6, and allow_loopback" do
      cases = [
        {"https://rp.example/backchannel", resolver([{93, 184, 216, 34}]), false},
        {"https://rp.example:8443/logout", resolver([{93, 184, 216, 34}]), false},
        {"https://rp.example/backchannel", resolver([], [{0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25C8, 0x1946}]),
         false},
        {"https://rp.example/backchannel", resolver([{169, 254, 169, 254}]), false},
        {"https://rp.example/backchannel", resolver([{10, 1, 2, 3}]), false},
        {"https://rp.example/backchannel", resolver([{127, 0, 0, 1}]), false},
        {"https://rp.example/backchannel", resolver([], [{0, 0, 0, 0, 0, 0, 0, 1}]), false},
        {"https://rp.example/backchannel", resolver([], [{0, 0, 0, 0, 0, 0xFFFF, 0xA01, 0x0203}]), false},
        {"https://rp.example/backchannel", resolver([], [{0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}]), false},
        {"https://rp.example/backchannel", resolver([{93, 184, 216, 34}], [{0, 0, 0, 0, 0, 0, 0, 1}]), false},
        {"https://rp.example/backchannel", resolver([], []), false},
        {"http://rp.example/cb", resolver([{93, 184, 216, 34}]), false},
        {"http://local.test/cb", resolver([{127, 0, 0, 1}]), true},
        {"http://local.test:4000/cb", resolver([], [{0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}]), true},
        {"https://local.test/cb", resolver([{169, 254, 169, 254}]), true}
      ]

      for {url, res, allow_loopback} <- cases do
        actual = OutboundTarget.screen(url, resolver: res, allow_loopback: allow_loopback)
        expected_ssrf = legacy_ssrf_screen(url, resolver: res, allow_loopback: allow_loopback)

        assert actual == expected_ssrf,
               "mismatch for #{url} (allow_loopback=#{allow_loopback}): #{inspect(actual)} vs #{inspect(expected_ssrf)}"

        if not allow_loopback do
          expected_discovery = legacy_discovery_screen(url, resolver: res)
          normalized = normalize_for_discovery(actual)

          assert normalized == expected_discovery,
                 "discovery mismatch for #{url}: #{inspect(normalized)} vs #{inspect(expected_discovery)}"
        end
      end
    end

    test "rejects invalid resolver and non-boolean allow_loopback" do
      bad_resolver = Process.get(:never_set, fn _host -> {:ok, []} end)

      assert {:error, :invalid_resolver} =
               OutboundTarget.screen("https://rp.example/cb", resolver: bad_resolver)

      for invalid <- ["false", 1, {:error, :unavailable}] do
        bad = Process.get(:never_set, invalid)

        assert_raise ArgumentError, ~r/:allow_loopback must be true or false/, fn ->
          OutboundTarget.screen("http://local.test/cb",
            resolver: resolver([{127, 0, 0, 1}]),
            allow_loopback: bad
          )
        end
      end
    end
  end

  defp normalize_for_discovery({:ok, target}), do: {:ok, target}
  defp normalize_for_discovery({:error, :invalid_resolver}), do: {:error, :invalid_resolver}
  defp normalize_for_discovery({:error, _reason}), do: {:error, :blocked_host}

  defp legacy_ssrf_screen(url, opts) do
    allow_loopback = Keyword.get(opts, :allow_loopback, false)
    res = Keyword.get(opts, :resolver, &:inet.getaddrs/2)

    with {:ok, %URI{scheme: scheme, host: host} = uri}
         when is_binary(host) and host != "" and
                (scheme == "https" or (allow_loopback and scheme == "http")) <- URI.new(url),
         ips when ips != [] <-
           legacy_lookup(res, host, :inet) ++ legacy_lookup(res, host, :inet6),
         nil <- Enum.find(ips, &legacy_blocked?(&1, allow_loopback)) do
      pinned = hd(ips)

      {:ok,
       %{
         url: URI.to_string(%{uri | host: pinned |> :inet.ntoa() |> to_string()}),
         host: uri.host,
         authority: OutboundTarget.authority(uri)
       }}
    else
      {:ok, _uri} -> {:error, :insecure_or_hostless_url}
      {:error, _} -> {:error, :invalid_url}
      [] -> {:error, :unresolvable}
      blocked when is_tuple(blocked) -> {:error, {:blocked_ip, blocked}}
    end
  end

  defp legacy_discovery_screen(url, opts) do
    res = Keyword.get(opts, :resolver, &:inet.getaddrs/2)

    if Attesto.URI.https_identifier?(url) do
      uri = URI.parse(url)
      ips = legacy_lookup(res, uri.host, :inet) ++ legacy_lookup(res, uri.host, :inet6)

      if ips != [] and not Enum.any?(ips, &(not Attesto.IPAddress.public_fetch_destination?(&1))) do
        pinned = hd(ips)

        {:ok,
         %{
           url: URI.to_string(%{uri | host: pinned |> :inet.ntoa() |> List.to_string()}),
           host: uri.host,
           authority: OutboundTarget.authority(uri)
         }}
      else
        {:error, :blocked_host}
      end
    else
      {:error, :blocked_host}
    end
  end

  defp legacy_lookup(res, host, family) do
    case res.(String.to_charlist(host), family) do
      {:ok, ips} when is_list(ips) -> ips
      _ -> []
    end
  end

  defp legacy_blocked?(ip, true), do: not legacy_loopback?(ip) and not Attesto.IPAddress.public_fetch_destination?(ip)

  defp legacy_blocked?(ip, false), do: not Attesto.IPAddress.public_fetch_destination?(ip)

  defp legacy_loopback?({127, _, _, _}), do: true
  defp legacy_loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp legacy_loopback?({0, 0, 0, 0, 0, 0xFFFF, w7, _}) when div(w7, 256) == 127, do: true
  defp legacy_loopback?(_), do: false
end
