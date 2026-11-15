defmodule Attesto.StatusListFetchTest do
  use ExUnit.Case, async: true

  alias Attesto.StatusList

  test "fetches bounded bytes with the requested media type and original host" do
    {url, server} = server(200, "application/statuslist+jwt; charset=utf-8", "signed-list")
    assert {:ok, "signed-list"} = StatusList.fetch(url, "application/statuslist+jwt", allow_loopback: true)
    assert {:ok, request} = Task.await(server)
    assert request =~ "accept: application/statuslist+jwt"
    assert request =~ "host: localhost:"
  end

  test "refuses redirects, wrong content types, oversized bodies and private destinations" do
    for {status, content_type, body, expected} <- [
          {302, "application/statuslist+jwt", "", {:http_status, 302}},
          {200, "text/html", "html", :invalid_status_list_content_type},
          {200, "application/statuslist+jwt", String.duplicate("x", StatusList.max_status_list_token_bytes() + 1),
           :too_large}
        ] do
      {url, server} = server(status, content_type, body)
      assert {:error, ^expected} = StatusList.fetch(url, "application/statuslist+jwt", allow_loopback: true)
      Task.await(server)
    end

    assert {:error, _} = StatusList.fetch("https://127.0.0.1/list", "application/statuslist+jwt")
    assert {:error, _} = StatusList.fetch("http://example.com/list", "application/statuslist+jwt")
  end

  test "the deadline includes DNS resolution and resolver exceptions fail closed" do
    resolver = fn _, _ ->
      Process.sleep(200)
      {:error, :nxdomain}
    end

    assert {:error, :status_list_fetch_timeout} =
             StatusList.fetch("https://issuer.example/list", "application/statuslist+jwt",
               timeout: 20,
               resolver: resolver
             )

    assert {:error, :status_list_fetch_failed} =
             StatusList.fetch("https://issuer.example/list", "application/statuslist+jwt",
               resolver: fn _, _ -> raise "DNS failed" end
             )
  end

  defp server(status, content_type, body) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, request} = :gen_tcp.recv(socket, 0, 5_000)

        :gen_tcp.send(socket, [
          "HTTP/1.1 #{status} Response\r\ncontent-type: #{content_type}\r\ncontent-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n",
          body
        ])

        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
        {:ok, String.downcase(request)}
      end)

    {"http://localhost:#{port}/list", task}
  end
end
