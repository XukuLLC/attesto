defmodule Attesto.Plug.ResourceProtectionTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.Plug.ProtectResource
  alias Attesto.Plug.ResourceMetadata
  alias Attesto.Plug.ResourceScopes

  test "scope hierarchies and offline_access are generic resource policies" do
    opts = ResourceScopes.init(scopes: ["offline_access", "read"], scope_hierarchy: %{"all" => ["read"]})
    conn = conn(:get, "/") |> assign(:attesto_scopes, ["offline_access", "all"])
    refute ResourceScopes.call(conn, opts).halted
  end

  test "metadata has no protocol scope catalog or bearer method default" do
    opts =
      ResourceMetadata.init(
        resource_path: "/archives",
        base_url: "https://api.example",
        issuer: "https://auth.example",
        scopes: ["offline_access"],
        authenticate: []
      )

    response = ResourceMetadata.call(conn(:get, "/"), opts)
    document = JSON.decode!(response.resp_body)
    assert document["scopes_supported"] == ["offline_access"]
    refute Map.has_key?(document, "bearer_methods_supported")
    refute Map.has_key?(document, "dpop_signing_alg_values_supported")
  end

  test "callback metadata is never publicly cached" do
    opts =
      ResourceMetadata.init(
        resource_path: "/a",
        base_url: fn _ -> "https://api.example" end,
        issuer: "https://auth.example"
      )

    response = ResourceMetadata.call(conn(:get, "/"), opts)
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "audience policy and DPoP pins fail closed at initialization" do
    assert_raise ArgumentError, ~r/pinned/, fn ->
      ProtectResource.init(config: :unused, resource_path: "/a", resource_audience: :resource, scopes: ["read"])
    end

    assert_raise ArgumentError, ~r/accepts DPoP requires/, fn ->
      ProtectResource.init(
        config: :unused,
        resource_audience: "https://api.example/a",
        scopes: ["read"],
        replay_check: fn _, _ -> :ok end
      )
    end

    assert_raise ArgumentError, ~r/HTTPS/, fn ->
      ProtectResource.init(
        config: :unused,
        resource_path: "/a",
        resource_audience: :resource,
        base_url: "http://remote.example",
        allow_http: true,
        scopes: ["read"]
      )
    end
  end

  test "a split boundary refuses preassigned claims even for an empty scope set" do
    protection = ProtectResource.prepare(config: :unused, resource_audience: "https://api.example/a")
    conn = conn(:get, "/a") |> assign(:attesto_claims, %{"sub" => "user"}) |> assign(:attesto_scopes, ["read"])
    response = ProtectResource.authorize(conn, protection, [])
    assert response.status == 401
    assert response.halted
    assert_raise ArgumentError, ~r/split/, fn -> ProtectResource.call(conn, protection) end
  end

  test "root metadata ownership is explicit for multiple resources" do
    assert {true, state} = Attesto.ResourceRoutes.mount(:auto)
    assert_raise ArgumentError, ~r/ambiguous/, fn -> Attesto.ResourceRoutes.mount(:auto, state) end
    assert {false, state} = Attesto.ResourceRoutes.mount(false)
    assert {false, _} = Attesto.ResourceRoutes.mount(false, state)
  end
end
