if Code.ensure_loaded?(Mint.HTTP) do
  defmodule Attesto.PinnedHTTP do
    @moduledoc """
    One-shot Mint HTTP/HTTPS client targeting a caller-screened IP literal while
    preserving TLS SNI and hostname verification for the original host.

    Hosts are expected to screen destinations via DNS resolution before calling
    this module and supply both the pinned literal URL and original hostname.
    Each call opens a single connection, enforces bounded response limits, and
    closes the socket immediately so attacker-controlled hostnames cannot
    accumulate persistent connection pools.
    """

    @protected_transport_options [
      :cb_info,
      :server_name_indication,
      :verify_fun,
      :customize_hostname_check,
      :partial_chain
    ]

    @type response :: %{status: non_neg_integer(), headers: [{binary(), binary()}], body: binary()}

    @type normalized_error ::
            {:transport, term()} | {:http, :http1 | :http2, term()} | term()

    @doc """
    Executes a bounded `:get` or `:post` request against `pinned_url` inside an
    isolated `Task` enforcing the wall-clock `timeout_ms` budget across
    connect, transmission, and active-socket response receipt.
    """
    @spec request(
            :get | :post,
            String.t(),
            String.t(),
            [{binary(), binary()}],
            binary(),
            pos_integer(),
            non_neg_integer() | :discard
          ) :: {:ok, response()} | {:error, term()}
    def request(method, pinned_url, hostname, headers, body, timeout_ms, body_limit) when method in [:get, :post] do
      if valid_active_request?(pinned_url, hostname, headers, body, timeout_ms, body_limit) do
        task =
          Task.async(fn ->
            do_active_request(method, pinned_url, hostname, headers, body, timeout_ms, body_limit)
          end)

        await_request(task, timeout_ms)
      else
        {:error, :invalid_request}
      end
    end

    @doc """
    Executes a bounded `:get` or `:post` request inline in the caller process
    using active-socket messages and the wall-clock `timeout_ms` deadline.
    """
    @spec request_inline(
            :get | :post,
            String.t(),
            String.t(),
            [{binary(), binary()}],
            binary(),
            pos_integer(),
            non_neg_integer() | :discard
          ) :: {:ok, response()} | {:error, term()}
    def request_inline(method, pinned_url, hostname, headers, body, timeout_ms, body_limit)
        when method in [:get, :post] do
      if valid_active_request?(pinned_url, hostname, headers, body, timeout_ms, body_limit) do
        do_active_request(method, pinned_url, hostname, headers, body, timeout_ms, body_limit)
      else
        {:error, :invalid_request}
      end
    end

    @doc false
    @spec passive_request(
            atom() | String.t(),
            URI.t(),
            [{binary(), binary()}],
            iodata() | nil,
            keyword(),
            (non_neg_integer(), [{binary(), binary()}] -> acc),
            (binary(), acc -> {:cont, acc} | {:halt, acc})
          ) :: {:ok, acc} | {:error, normalized_error()}
          when acc: var
    def passive_request(method, %URI{} = url, headers, body, opts, on_head, on_data)
        when is_list(headers) and is_list(opts) and is_function(on_head, 2) and is_function(on_data, 2) do
      connect_options = Keyword.get(opts, :connect_options, [])
      timeout = Keyword.get(opts, :receive_timeout, 15_000)
      hostname = Keyword.fetch!(connect_options, :hostname)

      base_transport =
        connect_options
        |> Keyword.take([:timeout])
        |> Keyword.merge(Keyword.get(connect_options, :transport_opts, []))

      protocols =
        Keyword.get_lazy(connect_options, :protocols, fn ->
          connect_options |> Keyword.get(:protocol, :http1) |> List.wrap()
        end)

      extra_mint_opts =
        connect_options
        |> Keyword.take([:client_settings])
        |> Keyword.merge(mode: :passive, protocols: protocols)

      with {:ok, conn} <- connect(url, hostname, base_transport, extra_mint_opts),
           {:ok, conn, ref} <-
             Mint.HTTP.request(
               conn,
               method |> to_string() |> String.upcase(),
               request_target(url),
               headers,
               body
             ) do
        receive_passive(conn, ref, timeout, {:head, nil, []}, on_head, on_data)
      else
        {:error, conn, reason} ->
          _ = Mint.HTTP.close(conn)
          {:error, normalize_mint_error(reason)}

        {:error, reason} ->
          {:error, normalize_mint_error(reason)}
      end
    end

    # Mint owns its socket through messages delivered to the process which
    # opened the connection. Isolating that process also means an outbound
    # request can neither consume nor reorder messages in its caller's mailbox.
    # Task.yield/2 supplies the outer wall-clock deadline, covering connect,
    # request transmission, and response receipt together.
    defp await_request(task, timeout_ms) do
      case Task.yield(task, timeout_ms) do
        {:ok, result} ->
          result

        {:exit, reason} ->
          {:error, reason}

        nil ->
          _ = Task.shutdown(task, :brutal_kill)
          {:error, :request_timeout}
      end
    end

    defp do_active_request(method, pinned_url, hostname, headers, body, timeout_ms, body_limit) do
      started_at = System.monotonic_time(:millisecond)

      with {:ok, uri} <- parse_url(pinned_url),
           {:ok, conn} <-
             connect(
               uri,
               hostname,
               [timeout: timeout_ms, send_timeout: timeout_ms],
               protocols: [:http1]
             ),
           {:ok, conn, request_ref} <-
             Mint.HTTP.request(
               conn,
               method |> Atom.to_string() |> String.upcase(),
               request_target(uri),
               headers,
               body
             ) do
        receive_active(
          conn,
          request_ref,
          started_at,
          timeout_ms,
          body_limit,
          %{status: nil, headers: [], body: ""}
        )
      else
        {:error, reason} -> {:error, reason}
        {:error, conn, reason} -> close_with_error(conn, reason)
      end
    rescue
      exception -> {:error, exception}
    catch
      kind, reason -> {:error, {kind, reason}}
    end

    defp valid_active_request?(pinned_url, hostname, headers, body, timeout_ms, body_limit) do
      is_binary(pinned_url) and is_binary(hostname) and is_list(headers) and is_binary(body) and
        is_integer(timeout_ms) and timeout_ms > 0 and valid_body_limit?(body_limit)
    end

    defp valid_body_limit?(:discard), do: true
    defp valid_body_limit?(limit), do: is_integer(limit) and limit >= 0

    defp parse_url(url) do
      case URI.new(url) do
        {:ok, %URI{scheme: scheme, host: host, port: port} = uri}
        when scheme in ["http", "https"] and is_binary(host) and host != "" and is_integer(port) ->
          {:ok, uri}

        _ ->
          {:error, :invalid_url}
      end
    end

    defp connect(%URI{scheme: scheme, host: address, port: port}, hostname, base_transport, extra_mint_opts) do
      transport_opts =
        base_transport
        |> Keyword.drop(@protected_transport_options)
        |> Keyword.merge(address_family_opts(address))
        |> maybe_verify_peer(scheme)

      mint_opts =
        Keyword.merge(extra_mint_opts,
          hostname: hostname,
          transport_opts: transport_opts
        )

      Mint.HTTP.connect(scheme_atom(scheme), address, port, mint_opts)
    end

    defp maybe_verify_peer(transport_opts, "https"), do: Keyword.put(transport_opts, :verify, :verify_peer)

    defp maybe_verify_peer(transport_opts, _scheme), do: transport_opts

    defp scheme_atom("https"), do: :https
    defp scheme_atom("http"), do: :http

    # The pinned URL carries the screened IP literal. Mint hands the address to
    # `:gen_tcp` / `:ssl`, which treat a string as an IPv4 host name unless the
    # socket is opened as `:inet6`, so an IPv6 literal must select that family.
    # IPv4 fallback is disabled because the literal has no IPv4 form.
    defp address_family_opts(address) do
      case :inet.parse_ipv6strict_address(String.to_charlist(address)) do
        {:ok, _ip} -> [inet6: true, inet4: false]
        {:error, _reason} -> []
      end
    end

    defp request_target(%URI{path: path, query: query}) do
      target = if path in [nil, ""], do: "/", else: path
      if query in [nil, ""], do: target, else: target <> "?" <> query
    end

    defp receive_active(conn, request_ref, started_at, timeout_ms, body_limit, response) do
      remaining = timeout_ms - (System.monotonic_time(:millisecond) - started_at)

      if remaining <= 0 do
        close_with_error(conn, :request_timeout)
      else
        socket = Mint.HTTP.get_socket(conn)

        receive do
          {tag, ^socket, _payload} = message when tag in [:tcp, :ssl, :tcp_error, :ssl_error] ->
            handle_active_message(conn, message, request_ref, started_at, timeout_ms, body_limit, response)

          {tag, ^socket} = message when tag in [:tcp_closed, :ssl_closed] ->
            handle_active_message(conn, message, request_ref, started_at, timeout_ms, body_limit, response)
        after
          remaining -> close_with_error(conn, :request_timeout)
        end
      end
    end

    defp handle_active_message(conn, message, request_ref, started_at, timeout_ms, body_limit, response) do
      case Mint.HTTP.stream(conn, message) do
        {:ok, next_conn, events} ->
          case fold_active_events(events, request_ref, body_limit, response) do
            {:cont, next_response} ->
              receive_active(next_conn, request_ref, started_at, timeout_ms, body_limit, next_response)

            {:done, completed} ->
              _ = Mint.HTTP.close(next_conn)
              {:ok, completed}

            {:error, reason} ->
              close_with_error(next_conn, reason)
          end

        {:error, next_conn, reason, _events} ->
          close_with_error(next_conn, reason)
      end
    end

    defp fold_active_events(events, request_ref, body_limit, response) do
      Enum.reduce_while(events, {:cont, response}, fn
        {:status, ^request_ref, status}, {:cont, acc} ->
          {:cont, {:cont, %{acc | status: status}}}

        {:headers, ^request_ref, headers}, {:cont, acc} ->
          {:cont, {:cont, %{acc | headers: acc.headers ++ headers}}}

        {:data, ^request_ref, _data}, {:cont, acc} when body_limit == :discard ->
          {:cont, {:cont, acc}}

        {:data, ^request_ref, data}, {:cont, acc} ->
          body = acc.body <> data

          if byte_size(body) > body_limit do
            {:halt, {:error, :too_large}}
          else
            {:cont, {:cont, %{acc | body: body}}}
          end

        {:done, ^request_ref}, {:cont, acc} ->
          {:halt, {:done, acc}}

        _other, current ->
          {:cont, current}
      end)
    end

    defp receive_passive(conn, ref, timeout, state, on_head, on_data) do
      case Mint.HTTP.recv(conn, 0, timeout) do
        {:ok, conn, responses} ->
          case handle_passive_responses(responses, ref, state, on_head, on_data) do
            {:cont, next_state} ->
              receive_passive(conn, ref, timeout, next_state, on_head, on_data)

            {:done, result} ->
              _ = Mint.HTTP.close(conn)
              result
          end

        {:error, conn, error, _responses} ->
          _ = Mint.HTTP.close(conn)
          {:error, normalize_mint_error(error)}
      end
    end

    defp handle_passive_responses([], _ref, state, _on_head, _on_data), do: {:cont, state}

    defp handle_passive_responses([response | rest], ref, state, on_head, on_data) do
      case handle_passive_response(response, ref, state, on_head, on_data) do
        {:cont, next_state} -> handle_passive_responses(rest, ref, next_state, on_head, on_data)
        {:done, _result} = done -> done
      end
    end

    # The state is `{:head, status, headers}` until body data arrives, then
    # `{:body, acc}`. A new status line (after a 1xx informational response)
    # starts a new head. Headers arriving after body data are trailers.
    defp handle_passive_response({:status, ref, status}, ref, {:head, _status, _headers}, _on_head, _on_data),
      do: {:cont, {:head, status, []}}

    defp handle_passive_response({:headers, ref, headers}, ref, {:head, status, acc}, _on_head, _on_data),
      do: {:cont, {:head, status, acc ++ headers}}

    defp handle_passive_response({:data, ref, _data} = data, ref, {:head, status, headers}, on_head, on_data),
      do: handle_passive_response(data, ref, {:body, on_head.(status, headers)}, on_head, on_data)

    defp handle_passive_response({:data, ref, data}, ref, {:body, acc}, _on_head, on_data) do
      case on_data.(data, acc) do
        {:cont, next_acc} -> {:cont, {:body, next_acc}}
        {:halt, done_acc} -> {:done, {:ok, done_acc}}
      end
    end

    defp handle_passive_response({:headers, ref, _trailers}, ref, {:body, _acc} = state, _on_head, _on_data),
      do: {:cont, state}

    defp handle_passive_response({:done, ref}, ref, {:head, status, headers}, on_head, _on_data),
      do: {:done, {:ok, on_head.(status, headers)}}

    defp handle_passive_response({:done, ref}, ref, {:body, acc}, _on_head, _on_data), do: {:done, {:ok, acc}}

    defp handle_passive_response({:error, ref, error}, ref, _state, _on_head, _on_data),
      do: {:done, {:error, normalize_mint_error(error)}}

    defp handle_passive_response({:push_promise, ref, _promised_ref, _headers}, ref, state, _on_head, _on_data),
      do: {:cont, state}

    defp handle_passive_response(response, ref, state, _on_head, _on_data) when elem(response, 1) != ref,
      do: {:cont, state}

    defp normalize_mint_error(%Mint.TransportError{reason: reason}), do: {:transport, reason}

    defp normalize_mint_error(%Mint.HTTPError{module: Mint.HTTP2, reason: reason}), do: {:http, :http2, reason}

    defp normalize_mint_error(%Mint.HTTPError{reason: reason}), do: {:http, :http1, reason}

    defp normalize_mint_error(reason), do: reason

    defp close_with_error(conn, reason) do
      _ = Mint.HTTP.close(conn)
      {:error, reason}
    end
  end
else
  defmodule Attesto.PinnedHTTP do
    @moduledoc false
    @dep_error ~s(Attesto.PinnedHTTP requires the optional :mint dependency. Add {:mint, ">= 1.10.2 and < 2.0.0"} to your deps.)

    @doc false
    def request(_method, _pinned_url, _hostname, _headers, _body, _timeout_ms, _body_limit),
      do: raise(RuntimeError, @dep_error)

    @doc false
    def request_inline(_method, _pinned_url, _hostname, _headers, _body, _timeout_ms, _body_limit),
      do: raise(RuntimeError, @dep_error)

    @doc false
    def passive_request(_method, _url, _headers, _body, _opts, _on_head, _on_data), do: raise(RuntimeError, @dep_error)
  end
end
