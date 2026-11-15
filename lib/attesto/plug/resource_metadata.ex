if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.ResourceMetadata do
    @moduledoc """
    Serve one RFC 9728 protected-resource document as JSON.

    Requires `:resource_path` and the options accepted by
    `Attesto.ResourceMetadata.protected_resource/3`. `:scopes` is an alias for
    `:scopes_supported`. Static pins permit public caching for one hour;
    callback or request-derived origins use no-store. `:metadata` optionally
    selects a protocol adapter with the same metadata builder contract.
    """
    @behaviour Plug

    alias Attesto.ResourceMetadata

    @impl Plug
    def init(opts) do
      ResourceMetadata.normalize_resource_path!(Keyword.fetch!(opts, :resource_path))
      ResourceMetadata.validate_metadata_options!(opts)
      opts
    end

    @impl Plug
    def call(conn, opts) do
      {path, opts} = Keyword.pop!(opts, :resource_path)
      {builder, opts} = Keyword.pop(opts, :metadata, ResourceMetadata)
      opts = ResourceMetadata.metadata_options(opts)
      document = builder.protected_resource(conn, path, opts)

      conn
      |> Plug.Conn.put_resp_header("cache-control", ResourceMetadata.cache_control(opts))
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, JSON.encode!(document))
    end
  end
end
