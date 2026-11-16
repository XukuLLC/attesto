defmodule Attesto.ClusterGuard do
  @moduledoc """
  Refuse to start a per-node ETS store on a clustered BEAM.

  Attesto's engine is pure and stateless, so it is cluster-safe by
  construction. The *state* (authorization codes, refresh-token families,
  seen DPoP `jti` values, DPoP nonces) lives behind storage behaviours
  whose contracts mandate atomic operations; a host implements them over a
  shared store (Postgres, Redis) for a multi-node deployment.

  The bundled ETS reference implementations are deliberately **single-node**:
  a captured code/token/proof would be replayable once per node if a second
  node held its own ETS copy, silently breaking single-use, reuse
  detection, and replay rejection. Rather than let that misconfiguration go
  unnoticed, the ordinary ETS stores call `assert_single_node!/2` at boot and
  **raises** if the BEAM is already clustered, unless the operator has
  explicitly acknowledged that they have wired a shared store and set the
  per-store `:multi_node_acknowledged?` option. `Attesto.DPoP.ReplayCache`
  instead requires an explicit `:single_node?` start option on every node.
  """

  require Logger

  @doc """
  Raise if `Node.list/0` is non-empty and the operator has not acknowledged
  a multi-node deployment.

  `module` names the store for the error message; `acknowledged?` is the
  store's `:multi_node_acknowledged?` flag.
  """
  @spec assert_single_node!(module(), boolean()) :: :ok
  def assert_single_node!(_module, true), do: :ok

  def assert_single_node!(module, false) do
    case Node.list() do
      [] ->
        :ok

      peers ->
        message =
          "#{inspect(module)} started on a clustered BEAM (peers=#{inspect(peers)}) but is a " <>
            "per-node ETS store. Its single-use / reuse / replay guarantees only hold across the " <>
            "deployment if every request for a credential reaches the same node. Implement the " <>
            "matching Attesto storage behaviour over a shared store (e.g. Postgres) for multi-node, " <>
            "or set multi_node_acknowledged?: true once you have. Refusing to boot."

        Logger.error("Attesto node-local store refused to start on a clustered BEAM",
          store: module,
          peers: inspect(peers)
        )

        raise RuntimeError, message
    end
  end
end
