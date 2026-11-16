if Code.ensure_loaded?(Mint.HTTP) do
  defmodule Attesto.PinnedHTTP do
    @moduledoc """
    Bounded HTTP requests to an `Attesto.OutboundTarget.screen/2` result.

    All entry points take the screened target and a keyword list. Connections
    use only its IP tuples, in order, cycling if necessary; no DNS lookup is
    performed here. TLS SNI, peer verification and the Host header use the
    original host and authority. Connections are closed after each response.

    Options shared by all three entry points:

      * `:method` - HTTP method (default `:get`).
      * `:headers` - header pairs (default `[]`); Host is set from the target.
      * `:body` - iodata or `nil` (default `nil`).
      * `:deadline` - absolute `System.monotonic_time(:millisecond)` deadline
        for the entire request (default: 15 seconds from entry).
      * `:receive_timeout` - streaming idle-read timeout in milliseconds
        (default `:infinity`), capped by the remaining deadline.
      * `:body_limit` - maximum response bytes (default 1 MiB), or `:discard`.
      * `:connect_timeout` - milliseconds per connection attempt (default
        3,000), always capped by the remaining deadline.
      * `:max_attempts` - positive attempt bound (default 3).
      * `:connect_options` - TLS trust/client certificates in `:transport_opts`,
        `:protocols` (default `[:http1]`) and `:client_settings`. Destination,
        peer verification, SNI, socket callbacks and timeouts cannot be replaced.
      * `:on_request` - zero-arity callback immediately before calling Mint's
        request function, for a supervising deadline to mark uncertain delivery.
        It must return promptly. Default: no callback.

    Only connection establishment (TCP and TLS handshake) is retried, on a
    fresh socket. After `Mint.HTTP.request/5` is called nothing is retried,
    including POSTs and errors returned by that function.

    `{:error, {:not_sent, cause}}` guarantees the request function was never
    called. Causes are normalized Mint errors (`{:transport, reason}` or
    `{:http, protocol, reason}`), `:deadline_exceeded`, or `:invalid_request`.
    An exhausted deadline during connect returns `:deadline_exceeded`; otherwise
    the last failed attempt supplies the cause. Invalid input is never retried.
    Every entry point returns `{:error, {:not_sent, cause}}` before that
    boundary or `{:error, {:maybe_sent, cause}}` after it. Both use the same
    causes: `{:transport, reason}`, `{:http, protocol, reason}`,
    `:deadline_exceeded`, `:too_large`, and `:invalid_request`. No Mint error
    struct is returned. Exceptions and caught exits/throws are guarded and
    classified at the same boundary; unexpected failures are transport causes.
    """

    @protected_transport_options [
      :cb_info,
      :server_name_indication,
      :verify_fun,
      :customize_hostname_check,
      :partial_chain,
      :timeout,
      :send_timeout,
      :inet_backend,
      :ip,
      :ifaddr,
      :fd
    ]
    @type response :: %{status: non_neg_integer(), headers: [{binary(), binary()}], body: binary()}
    @type cause ::
            {:transport, term()} | {:http, :http1 | :http2, term()} | :deadline_exceeded | :too_large | :invalid_request
    @type normalized_error :: {:not_sent | :maybe_sent, cause()}

    @doc "Runs the request in an isolated process without consuming caller socket messages."
    @spec request(Attesto.OutboundTarget.screened(), keyword()) :: {:ok, response()} | {:error, normalized_error()}
    def request(target, opts \\ []) do
      with {:ok, config} <- configuration(target, opts) do
        task = Task.async(fn -> do_request(target, config, :active) end)

        await_request(task, config)
      end
    end

    defp await_request(task, config) do
      case Task.yield(task, max(0, remaining(config)) + 50) do
        {:ok, result} ->
          result

        {:exit, reason} ->
          request_error(config, reason)

        nil ->
          Task.shutdown(task, :brutal_kill)

          request_error(config, :deadline_exceeded)
      end
    end

    @doc "Runs the request inline, consuming only messages for its own socket."
    @spec request_inline(Attesto.OutboundTarget.screened(), keyword()) ::
            {:ok, response()} | {:error, normalized_error()}
    def request_inline(target, opts \\ []) do
      with {:ok, config} <- configuration(target, opts), do: do_request(target, config, :active)
    end

    @doc """
    Streams a passive response. Requires `:on_head` (status, headers -> acc) and
    `:on_data` (data, acc -> `{:cont, acc}` or `{:halt, acc}`) options.
    Returns `{:ok, acc}` on completion or callback halt. `:discard` skips data
    callbacks. The body limit and absolute deadline still apply to the stream.
    """
    @spec passive_request(Attesto.OutboundTarget.screened(), keyword()) :: {:ok, term()} | {:error, normalized_error()}
    def passive_request(target, opts \\ []) do
      with {:ok, config} <- configuration(target, opts) do
        if is_function(config.on_head, 2) and is_function(config.on_data, 2),
          do: do_request(target, config, :passive),
          else: {:error, {:not_sent, :invalid_request}}
      end
    end

    defp configuration(target, opts) when is_map(target) and is_list(opts) do
      config = %{
        phase: :atomics.new(1, []),
        deadline: Keyword.get(opts, :deadline, System.monotonic_time(:millisecond) + 15_000),
        connect_timeout: Keyword.get(opts, :connect_timeout, 3_000),
        max_attempts: Keyword.get(opts, :max_attempts, 3),
        receive_timeout: Keyword.get(opts, :receive_timeout, :infinity),
        body_limit: Keyword.get(opts, :body_limit, 1_048_576),
        method: Keyword.get(opts, :method, :get),
        headers: Keyword.get(opts, :headers, []),
        body: Keyword.get(opts, :body),
        connect_options: Keyword.get(opts, :connect_options, []),
        on_request: Keyword.get(opts, :on_request, fn -> :ok end),
        on_head: Keyword.get(opts, :on_head),
        on_data: Keyword.get(opts, :on_data)
      }

      with %{url: url, host: host, authority: authority, addresses: [_ | _] = addresses} <- target,
           {:ok, %URI{scheme: scheme, host: ^host, port: port} = uri} <- URI.new(url),
           true <- scheme in ["http", "https"] and is_integer(port),
           true <- is_binary(authority) and Enum.all?(addresses, &valid_ip?/1),
           true <- valid_config?(config) do
        {:ok, Map.put(config, :uri, uri)}
      else
        _ -> {:error, {:not_sent, :invalid_request}}
      end
    rescue
      _ -> {:error, {:not_sent, :invalid_request}}
    end

    defp configuration(_target, _opts), do: {:error, {:not_sent, :invalid_request}}

    defp valid_config?(config) do
      valid_limits?(config) and valid_request?(config) and
        is_list(config.connect_options) and is_function(config.on_request, 0)
    end

    defp valid_limits?(config) do
      is_integer(config.deadline) and positive?(config.connect_timeout) and positive?(config.max_attempts) and
        valid_body_limit?(config.body_limit) and valid_receive_timeout?(config.receive_timeout)
    end

    defp positive?(value), do: is_integer(value) and value > 0
    defp valid_body_limit?(:discard), do: true
    defp valid_body_limit?(value), do: is_integer(value) and value >= 0
    defp valid_receive_timeout?(:infinity), do: true
    defp valid_receive_timeout?(value), do: positive?(value)

    defp valid_request?(config) do
      (is_atom(config.method) or is_binary(config.method)) and
        is_list(config.headers) and Enum.all?(config.headers, &valid_header?/1) and
        (is_nil(config.body) or is_integer(IO.iodata_length(config.body)))
    end

    defp valid_header?({name, value}), do: is_binary(name) and is_binary(value)
    defp valid_header?(_header), do: false

    defp valid_ip?(ip) when is_tuple(ip), do: is_list(:inet.ntoa(ip))
    defp valid_ip?(_ip), do: false
    defp remaining(config), do: config.deadline - System.monotonic_time(:millisecond)

    defp do_request(target, config, mode) do
      with {:ok, conn} <- connect_attempt(target, config, mode, 1) do
        if remaining(config) <= 0 do
          Mint.HTTP.close(conn)
          {:error, {:not_sent, :deadline_exceeded}}
        else
          send_request(conn, target, config, mode)
        end
      end
    rescue
      error -> request_error(config, error)
    catch
      kind, reason -> request_error(config, {kind, reason})
    end

    defp send_request(conn, target, config, mode) do
      headers = [
        {"host", target.authority}
        | Enum.reject(config.headers, fn {name, _} ->
            String.downcase(to_string(name)) == "host"
          end)
      ]

      method = config.method |> to_string() |> String.upcase()
      path = request_target(config.uri)
      config.on_request.()
      issue_request(conn, method, path, headers, config, mode)
    rescue
      error -> request_error(config, error)
    catch
      kind, reason -> request_error(config, {kind, reason})
    after
      Mint.HTTP.close(conn)
    end

    defp issue_request(conn, method, path, headers, config, mode) do
      :atomics.put(config.phase, 1, 1)

      result =
        case Mint.HTTP.request(conn, method, path, headers, config.body) do
          {:ok, conn, ref} -> consume(conn, ref, config, mode)
          {:error, conn, reason} -> close_with_error(conn, reason)
        end

      case result do
        {:error, reason} -> {:error, {:maybe_sent, normalize_mint_error(reason)}}
        success -> success
      end
    rescue
      error -> {:error, {:maybe_sent, normalize_mint_error(error)}}
    catch
      kind, reason -> {:error, {:maybe_sent, normalize_mint_error({kind, reason})}}
    end

    # The same marker covers worker timeout, preparation, response consumption
    # and cleanup exceptions in every entry point.
    defp request_error(config, reason) do
      certainty = if :atomics.get(config.phase, 1) == 0, do: :not_sent, else: :maybe_sent
      {:error, {certainty, normalize_mint_error(reason)}}
    end

    defp consume(conn, ref, config, :active) do
      receive_active(conn, ref, config.deadline, config.body_limit, %{status: nil, headers: [], body: ""})
    end

    defp consume(conn, ref, config, :passive) do
      receive_passive(conn, ref, config, {:head, nil, []}, config.on_head, config.on_data, 0)
    end

    defp connect_attempt(target, config, mode, attempt) do
      if remaining(config) <= 0 do
        {:error, {:not_sent, :deadline_exceeded}}
      else
        address = Enum.at(target.addresses, rem(attempt - 1, length(target.addresses)))
        started = System.monotonic_time()
        result = bounded_connect(address, target.host, config, mode)

        Attesto.Telemetry.connect_attempt(
          System.monotonic_time() - started,
          %{address: address, attempt: attempt, outcome: if(match?({:ok, _}, result), do: :ok, else: :error)}
        )

        case result do
          {:ok, conn} -> {:ok, conn}
          {:error, reason} -> retry_connect(target, config, mode, attempt, reason)
        end
      end
    end

    defp retry_connect(target, config, mode, attempt, reason) do
      cond do
        remaining(config) <= 0 -> {:error, {:not_sent, :deadline_exceeded}}
        attempt < config.max_attempts -> connect_attempt(target, config, mode, attempt + 1)
        true -> {:error, {:not_sent, normalize_mint_error(reason)}}
      end
    end

    # Bound the entire Mint connect, including TLS option/trust preparation.
    # A socket is reported before ownership transfer, so even a timeout racing
    # that transfer can close it. Failed workers close sockets they still own.
    defp bounded_connect(address, hostname, config, mode) do
      owner = self()
      ref = make_ref()

      task =
        Task.async(fn -> transfer_connection(address, hostname, config, owner, ref) end)

      result =
        Task.yield(task, max(0, min(config.connect_timeout, remaining(config)))) ||
          Task.shutdown(task, :brutal_kill)

      socket_conn =
        receive do
          {^ref, conn} -> conn
        after
          0 -> nil
        end

      case result do
        {:ok, {:ok, conn}} ->
          case Mint.HTTP.set_mode(conn, mode) do
            {:ok, conn} ->
              {:ok, conn}

            {:error, reason} ->
              Mint.HTTP.close(conn)
              {:error, reason}
          end

        other ->
          if socket_conn, do: Mint.HTTP.close(socket_conn)
          connect_failure(other)
      end
    end

    defp transfer_connection(address, hostname, config, owner, ref) do
      with {:ok, conn} <- connect(address, hostname, config, :passive) do
        send(owner, {ref, conn})
        Mint.HTTP.controlling_process(conn, owner)
      end
    rescue
      error -> {:error, error}
    catch
      kind, reason -> {:error, {kind, reason}}
    end

    defp connect_failure({:ok, {:error, reason}}), do: {:error, reason}
    defp connect_failure({:exit, reason}), do: {:error, reason}
    defp connect_failure(nil), do: {:error, %Mint.TransportError{reason: :timeout}}

    defp connect(address, hostname, config, mode) do
      timeout = max(1, min(config.connect_timeout, remaining(config)))

      transport_opts =
        config.connect_options
        |> Keyword.get(:transport_opts, [])
        |> Keyword.drop(@protected_transport_options ++ [:inet6, :inet4])
        |> Keyword.merge(timeout: timeout, send_timeout: max(1, remaining(config)))
        |> Keyword.merge(if tuple_size(address) == 8, do: [inet6: true, inet4: false], else: [])
        |> maybe_verify_peer(config.uri.scheme)

      mint_opts =
        config.connect_options
        |> Keyword.take([:client_settings, :protocols])
        |> Keyword.put_new(:protocols, [:http1])
        |> Keyword.merge(hostname: hostname, transport_opts: transport_opts, mode: mode)

      Mint.HTTP.connect(scheme_atom(config.uri.scheme), address, config.uri.port, mint_opts)
    rescue
      error -> {:error, error}
    catch
      kind, reason -> {:error, {kind, reason}}
    end

    defp maybe_verify_peer(opts, "https"), do: Keyword.put(opts, :verify, :verify_peer)
    defp maybe_verify_peer(opts, _scheme), do: opts
    defp scheme_atom("https"), do: :https
    defp scheme_atom("http"), do: :http

    defp request_target(%URI{path: path, query: query}) do
      target = if path in [nil, ""], do: "/", else: path
      if query in [nil, ""], do: target, else: target <> "?" <> query
    end

    defp receive_active(conn, request_ref, deadline, body_limit, response) do
      remaining = deadline - System.monotonic_time(:millisecond)

      if remaining <= 0 do
        close_with_error(conn, :deadline_exceeded)
      else
        socket = Mint.HTTP.get_socket(conn)

        receive do
          {tag, ^socket, _payload} = message when tag in [:tcp, :ssl, :tcp_error, :ssl_error] ->
            handle_active_message(conn, message, request_ref, deadline, body_limit, response)

          {tag, ^socket} = message when tag in [:tcp_closed, :ssl_closed] ->
            handle_active_message(conn, message, request_ref, deadline, body_limit, response)
        after
          remaining -> close_with_error(conn, :deadline_exceeded)
        end
      end
    end

    defp handle_active_message(conn, message, request_ref, deadline, body_limit, response) do
      case Mint.HTTP.stream(conn, message) do
        {:ok, next_conn, events} ->
          case fold_active_events(events, request_ref, body_limit, response) do
            {:cont, next_response} ->
              receive_active(next_conn, request_ref, deadline, body_limit, next_response)

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

    defp receive_passive(conn, ref, config, state, on_head, on_data, bytes) do
      if remaining(config) <= 0 do
        close_with_error(conn, :deadline_exceeded)
      else
        recv_passive(conn, ref, config, state, on_head, on_data, bytes)
      end
    end

    defp recv_passive(conn, ref, config, state, on_head, on_data, bytes) do
      case Mint.HTTP.recv(conn, 0, max(0, min(remaining(config), config.receive_timeout))) do
        {:ok, conn, responses} ->
          bytes = bytes + response_bytes(responses, ref)

          case passive_events(responses, ref, config.body_limit, bytes, state, on_head, on_data) do
            {:cont, next_state} ->
              receive_passive(conn, ref, config, next_state, on_head, on_data, bytes)

            {:done, result} ->
              Mint.HTTP.close(conn)
              result
          end

        {:error, conn, error, _responses} ->
          reason = if remaining(config) <= 0, do: :deadline_exceeded, else: error
          close_with_error(conn, reason)
      end
    end

    defp response_bytes(responses, ref) do
      Enum.reduce(responses, 0, fn
        {:data, ^ref, data}, size -> size + byte_size(data)
        _, size -> size
      end)
    end

    defp passive_events(responses, ref, :discard, _bytes, state, on_head, _on_data),
      do: handle_passive_responses(responses, ref, state, on_head, fn _, acc -> {:cont, acc} end)

    defp passive_events(_responses, _ref, limit, bytes, _state, _on_head, _on_data) when bytes > limit,
      do: {:done, {:error, :too_large}}

    defp passive_events(responses, ref, _limit, _bytes, state, on_head, on_data),
      do: handle_passive_responses(responses, ref, state, on_head, on_data)

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

    defp normalize_mint_error(%Mint.TransportError{reason: reason}), do: {:transport, error_detail(reason)}

    defp normalize_mint_error(%Mint.HTTPError{module: Mint.HTTP2, reason: reason}),
      do: {:http, :http2, error_detail(reason)}

    defp normalize_mint_error(%Mint.HTTPError{reason: reason}), do: {:http, :http1, error_detail(reason)}

    defp normalize_mint_error(reason) when reason in [:deadline_exceeded, :too_large, :invalid_request], do: reason
    defp normalize_mint_error({:transport, reason}), do: {:transport, error_detail(reason)}
    defp normalize_mint_error({:http, protocol, reason}), do: {:http, protocol, error_detail(reason)}
    defp normalize_mint_error(reason), do: {:transport, error_detail(reason)}

    defp error_detail(%Mint.TransportError{} = error), do: normalize_mint_error(error)
    defp error_detail(%Mint.HTTPError{} = error), do: normalize_mint_error(error)

    defp error_detail(value) when is_tuple(value),
      do: value |> Tuple.to_list() |> Enum.map(&error_detail/1) |> List.to_tuple()

    defp error_detail([head | tail]), do: [error_detail(head) | error_detail(tail)]

    defp error_detail(value) when is_map(value),
      do: value |> Map.to_list() |> Map.new(fn {key, item} -> {error_detail(key), error_detail(item)} end)

    defp error_detail(value), do: value

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
    def request(_target, _opts \\ []), do: raise(RuntimeError, @dep_error)
    @doc false
    def request_inline(_target, _opts \\ []), do: raise(RuntimeError, @dep_error)
    @doc false
    def passive_request(_target, _opts \\ []), do: raise(RuntimeError, @dep_error)
  end
end
