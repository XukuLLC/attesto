defmodule Attesto.PinnedHTTPTest do
  use ExUnit.Case, async: false

  alias Attesto.{OutboundTarget, PinnedHTTP}

  setup do
    id = {__MODULE__, make_ref()}
    :ok = :telemetry.attach(id, [:attesto, :http, :connect_attempt], &__MODULE__.event/4, self())
    on_exit(fn -> :telemetry.detach(id) end)
  end

  def event(_event, measurements, metadata, parent), do: send(parent, {:attempt, measurements, metadata})

  for entry <- [:request, :request_inline, :passive_request] do
    @entry entry
    test "#{entry}: refused connections stop at the bound without sending a POST" do
      {listener, port} = tcp_listener()
      :gen_tcp.close(listener)
      target = target(port)

      assert {:error, {:not_sent, {:transport, :econnrefused}}} =
               call(@entry, target, max_attempts: 4)

      for attempt <- 1..4 do
        assert_receive {:attempt, %{duration: duration}, %{attempt: ^attempt, outcome: :error}}
        assert duration >= 0
      end

      refute_received {:attempt, _, _}
    end

    test "#{entry}: a POST read before a disconnect is never retried" do
      {listener, port} = tcp_listener()
      parent = self()

      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        request = read_request(:gen_tcp, socket, "")
        send(parent, {:request, request})
        :gen_tcp.close(socket)
        send(parent, {:second_connection, :gen_tcp.accept(listener, 150)})
      end)

      assert {:error, {:maybe_sent, {:transport, :closed}}} = call(@entry, target(port))
      assert_receive {:request, request}
      assert request =~ "POST /token?private=query HTTP/1.1"
      assert request =~ "body=once"
      assert_receive {:attempt, _, %{attempt: 1, outcome: :ok}}
      refute_received {:attempt, _, _}
      assert_receive {:second_connection, {:error, :timeout}}, 1_000
    end

    test "#{entry}: guards exceptions, throws and exits before the request boundary" do
      for callback <- [
            fn -> raise "callback failed" end,
            fn -> throw(:callback_failed) end,
            fn -> exit(:callback_failed) end
          ] do
        {listener, port} = tcp_listener()
        parent = self()

        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)
          send(parent, {:no_request, :gen_tcp.recv(socket, 0, 2_000)})
          :gen_tcp.close(socket)
        end)

        assert {:error, {:not_sent, {:transport, _cause}}} =
                 call(@entry, target(port), on_request: callback)

        assert_receive {:no_request, {:error, :closed}}
        assert_receive {:attempt, _, %{attempt: 1, outcome: :ok}}
        refute_received {:attempt, _, _}
      end
    end

    test "#{entry}: normalizes protocol errors after entering the request function" do
      {listener, port} = tcp_listener()

      assert {:error, {:maybe_sent, {:http, :http1, {:invalid_request_method, "BAD METHOD"}}}} =
               call(@entry, target(port), method: "BAD METHOD")

      :gen_tcp.close(listener)
      assert_receive {:attempt, _, %{attempt: 1, outcome: :ok}}
      refute_received {:attempt, _, _}
    end

    test "#{entry}: response size and deadline failures retain delivery certainty" do
      for {response, opts, cause} <- [
            {"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nbody", [body_limit: 2], :too_large},
            {"", [deadline: System.monotonic_time(:millisecond) + 200], :deadline_exceeded}
          ] do
        {listener, port} = tcp_listener()

        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)
          read_request(:gen_tcp, socket, "")
          :gen_tcp.send(socket, response)
          :gen_tcp.recv(socket, 0, 1_000)
          :gen_tcp.close(socket)
        end)

        assert {:error, {:maybe_sent, ^cause}} = call(@entry, target(port), opts)
        assert_receive {:attempt, _, %{attempt: 1, outcome: :ok}}
        refute_received {:attempt, _, _}
      end
    end

    @tag :capture_log
    test "#{entry}: a failed handshake is retried on a fresh connection and sends one POST" do
      parent = self()

      {port, trust} =
        tls_listener(fn listener ->
          {:ok, first} = :ssl.transport_accept(listener, 2_000)
          :ssl.handshake(first, [versions: [:"tlsv1.2"]], 2_000)
          :ssl.close(first)
          {:ok, second} = :ssl.transport_accept(listener, 2_000)
          {:ok, second} = :ssl.handshake(second, 2_000)
          request = read_request(:ssl, second, "")
          send(parent, {:request, request})
          :ssl.send(second, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
          :ssl.close(second)
          send(parent, {:third_connection, :ssl.transport_accept(listener, 150)})
        end)

      started = System.monotonic_time(:millisecond)

      assert {:ok, %{status: 200, body: "ok"}} =
               call(@entry, target(port, "https"),
                 connect_options: [transport_opts: [cacerts: trust, versions: [:"tlsv1.3"]]]
               )

      assert System.monotonic_time(:millisecond) - started < 2_000
      assert_receive {:request, request}
      assert request =~ "body=once"
      assert request =~ "host: screened.example:#{port}"
      assert_receive {:attempt, _, %{attempt: 1, outcome: :error}}
      assert_receive {:attempt, _, %{attempt: 2, outcome: :ok}}
      refute_received {:attempt, _, _}
      assert_receive {:third_connection, {:error, :timeout}}, 1_000
    end

    @tag :capture_log
    test "#{entry}: the deadline ends during TLS connect with a not-sent result" do
      {listener, port} = tcp_listener()
      parent = self()

      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        send(parent, :accepted)
        # A TCP peer that never completes TLS cannot receive an HTTP request.
        receive do
          :finish -> :ok
        after
          1_000 -> :ok
        end

        :gen_tcp.close(socket)
      end)

      started = System.monotonic_time(:millisecond)

      assert {:error, {:not_sent, :deadline_exceeded}} =
               call(@entry, target(port, "https"), deadline: started + 100, connect_timeout: 5_000)

      assert System.monotonic_time(:millisecond) - started < 500
      assert_receive :accepted
      assert_receive {:attempt, _, %{attempt: 1, outcome: :error}}
      refute_received {:attempt, _, _}
    end
  end

  test "caught terms cannot carry Mint structs out of the module" do
    for entry <- [:request, :request_inline, :passive_request] do
      {listener, port} = tcp_listener()

      assert {:error, {:not_sent, {:transport, {:throw, {:transport, :closed}}}}} =
               call(entry, target(port), on_request: fn -> throw(%Mint.TransportError{reason: :closed}) end)

      :gen_tcp.close(listener)
    end
  end

  test "stream callback exceptions, exits and throws are maybe-sent transport failures" do
    for callback <- [
          fn _, _ -> raise "collector failed" end,
          fn _, _ -> throw(:collector_failed) end,
          fn _, _ -> exit(:collector_failed) end
        ] do
      {listener, port} = tcp_listener()
      parent = self()

      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        read_request(:gen_tcp, socket, "")
        :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
        send(parent, {:closed, :gen_tcp.recv(socket, 0, 2_000)})
        :gen_tcp.close(socket)
      end)

      assert {:error, {:maybe_sent, {:transport, _cause}}} =
               call(:passive_request, target(port), on_head: callback)

      assert_receive {:closed, {:error, :closed}}
      assert_receive {:attempt, _, %{attempt: 1, outcome: :ok}}
      refute_received {:attempt, _, _}
    end
  end

  test "attempts rotate only through the screened IPv4 and IPv6 addresses" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, :inet6, ip: {0, 0, 0, 0, 0, 0, 0, 1}, active: false])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, port} = :inet.port(listener)
    parent = self()

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listener, 2_000)
      send(parent, {:request, read_request(:gen_tcp, socket, "")})
      :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
      :gen_tcp.close(socket)
    end)

    ipv6 = {0, 0, 0, 0, 0, 0, 0, 1}
    resolver = fn _, family -> if family == :inet, do: {:ok, [{127, 0, 0, 1}]}, else: {:ok, [ipv6]} end

    assert {:ok, target} =
             OutboundTarget.screen("http://never-resolve.example:#{port}/token?private=query",
               resolver: resolver,
               allow_loopback: true
             )

    assert {:ok, %{body: "ok"}} = call(:request, target)
    assert_receive {:attempt, _, %{address: {127, 0, 0, 1}, attempt: 1, outcome: :error}}
    assert_receive {:attempt, _, %{address: ^ipv6, attempt: 2, outcome: :ok} = metadata}
    assert Map.keys(metadata) |> Enum.sort() == [:address, :attempt, :outcome]
  end

  test "an expired deadline and invalid options open no connection" do
    for entry <- [:request, :request_inline, :passive_request] do
      assert {:error, {:not_sent, :deadline_exceeded}} =
               call(entry, target(1), deadline: System.monotonic_time(:millisecond) - 1)

      assert {:error, {:not_sent, :invalid_request}} = call(entry, target(1), max_attempts: 0)
      assert {:error, {:not_sent, :invalid_request}} = call(entry, %{target(1) | addresses: [~c"localhost"]})
    end

    refute_received {:attempt, _, _}
  end

  defp call(entry, target, opts \\ []) do
    opts =
      Keyword.merge(
        [
          method: :post,
          body: "body=once",
          deadline: System.monotonic_time(:millisecond) + 2_000,
          on_head: fn status, headers -> %{status: status, headers: headers, body: ""} end,
          on_data: fn data, acc -> {:cont, %{acc | body: acc.body <> data}} end
        ],
        opts
      )

    apply(PinnedHTTP, entry, [target, opts])
  end

  defp target(port, scheme \\ "http") do
    {:ok, target} =
      OutboundTarget.screen("#{scheme}://screened.example:#{port}/token?private=query",
        allow_loopback: true,
        resolver: fn _, family ->
          if family == :inet, do: {:ok, [{127, 0, 0, 1}]}, else: {:ok, []}
        end
      )

    target
  end

  defp tcp_listener do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, port} = :inet.port(listener)
    {listener, port}
  end

  defp tls_listener(serve) do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
    san = {:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"screened.example"]}

    data =
      :public_key.pkix_test_data(%{
        root: [key: curve, digest: :sha256],
        intermediates: [],
        peer: [key: curve, digest: :sha256, extensions: [san]]
      })

    parent = self()

    pid =
      spawn_link(fn ->
        {:ok, listener} =
          :ssl.listen(0, ip: {127, 0, 0, 1}, active: false, mode: :binary, cert: data[:cert], key: data[:key])

        {:ok, {_, port}} = :ssl.sockname(listener)
        send(parent, {:port, port})
        serve.(listener)
        :ssl.close(listener)
      end)

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    assert_receive {:port, port}
    {port, data[:cacerts]}
  end

  defp read_request(transport, socket, acc) do
    if String.contains?(acc, "\r\n\r\n") and String.ends_with?(acc, "body=once") do
      acc
    else
      {:ok, data} = transport.recv(socket, 0, 2_000)
      read_request(transport, socket, acc <> data)
    end
  end
end
