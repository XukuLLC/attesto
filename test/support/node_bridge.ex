defmodule Attesto.Test.NodeBridge do
  @moduledoc """
  Node.js reference bridge for the cross-language parity tests.

  Runs a persistent pool of Node workers over Ports (the `nodejs` package) and
  calls into the JavaScript JOSE reference (`jose`) in `test/support/js`. This
  is the JavaScript counterpart to `Attesto.Test.PythonBridge` (joserfc /
  cryptography): it confirms Attesto's tokens, thumbprints, and DPoP proofs are
  RFC-conformant wire in the largest JWT ecosystem, not just against a Python
  stack. Test-support only - never part of the shipped library (the package's
  `files` list ships `lib` only).

  ## Requirements

  Node.js on `PATH` and the JS deps installed:

      cd test/support/js && npm install   # installs `jose`

  `availability/0` reports whether the Node pool starts and `jose` loads, so a
  parity module can skip cleanly on a machine without the JS stack rather than
  failing the suite.
  """

  @js_dir Path.expand("js", __DIR__)

  @doc "Absolute path to the JS JOSE reference directory."
  @spec js_dir() :: binary()
  def js_dir, do: @js_dir

  @doc """
  Start the Node worker pool if not already running. Idempotent. Raises with
  the failure reason on startup failure.
  """
  @spec ensure_started!() :: :ok
  def ensure_started! do
    case NodeJS.start_link(path: @js_dir, pool_size: 2) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      {:error, reason} -> raise "Failed to start Node.js pool: #{inspect(reason)}"
    end
  end

  @doc """
  Call an exported JS function, raising on a JS error so a failure surfaces as
  a real test failure rather than a silently-ignored `{:error, _}`.

      Attesto.Test.NodeBridge.call!("attesto_compat", :verifyJwt, [token, pem, "PS256"])
  """
  @spec call!(binary(), atom() | binary(), list()) :: term()
  def call!(module, fun, args) when is_binary(module) and is_list(args) do
    ensure_started!()

    case NodeJS.call({module, to_string(fun)}, args) do
      {:ok, result} -> result
      {:error, reason} -> raise "Node.js error in #{module}.#{fun}: #{inspect(reason)}"
    end
  end

  @doc """
  Whether the bridge can run: Node is on `PATH`, the JS deps are installed, and
  the pool starts with `jose` loadable. Returns `:ok` or `{:skip, reason}` so a
  parity module can self-skip on a machine without the JS stack.
  """
  @spec availability() :: :ok | {:skip, binary()}
  def availability do
    cond do
      System.find_executable("node") == nil ->
        {:skip, "node not on PATH"}

      not File.dir?(Path.join(@js_dir, "node_modules")) ->
        {:skip, "JS deps not installed (run `npm install` in #{@js_dir})"}

      true ->
        try do
          "pong" = call!("attesto_compat", :ping, [])
          :ok
        rescue
          e -> {:skip, "Node bridge unavailable: #{Exception.message(e)}"}
        catch
          kind, reason -> {:skip, "Node bridge unavailable: #{inspect({kind, reason})}"}
        end
    end
  end
end
