defmodule Attesto.Plug.RequireScopesTest do
  @moduledoc false
  # Drives the scope-authorization plug directly: pre-assign verified claims
  # onto the conn (as Attesto.Plug.Authenticate would) and call/2. Pure conn
  # work with no keystore or app env, so the module is async-safe.
  use ExUnit.Case, async: true

  import Plug.Test

  alias Attesto.Plug.RequireScopes

  defp with_claims(claims) do
    conn(:get, "https://api.example.com/x")
    |> Plug.Conn.assign(:attesto_claims, claims)
  end

  describe "init/1" do
    test "raises ArgumentError on an empty list" do
      assert_raise ArgumentError, fn -> RequireScopes.init([]) end
    end

    test "raises ArgumentError on a keyword list with no scopes" do
      assert_raise ArgumentError, fn -> RequireScopes.init(scopes: []) end
    end

    test "builds the required set + catalog from a bare scope list" do
      opts = RequireScopes.init(["documents.read"])
      assert opts.required == ["documents.read"]
    end

    test "accepts a keyword list with :scopes and :claims_key" do
      opts = RequireScopes.init(scopes: ["documents.read"], claims_key: :other_claims)
      assert opts.required == ["documents.read"]
      assert opts.claims_key == :other_claims
    end
  end

  describe "call/2" do
    test "passes through (conn not halted) when scope covers the requirement" do
      opts = RequireScopes.init(["documents.read"])

      conn =
        %{"scope" => "documents.read positions.read"}
        |> with_claims()
        |> RequireScopes.call(opts)

      refute conn.halted
      assert conn.status == nil
    end

    test "403 insufficient_scope with a scope WWW-Authenticate param on missing scope" do
      opts = RequireScopes.init(["documents.write"])

      conn =
        %{"scope" => "documents.read"}
        |> with_claims()
        |> RequireScopes.call(opts)

      assert conn.status == 403
      assert conn.halted

      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(error="insufficient_scope")
      assert challenge =~ ~s(scope="documents.write")
      # A bearer (no cnf.jkt) token gets a Bearer challenge.
      assert String.starts_with?(challenge, "Bearer ")
      assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
    end

    test "403 insufficient_scope on a DPoP-bound token answers with a DPoP challenge" do
      # RFC 9449 §7.1: the challenge scheme must match how the client
      # authenticated. A token carrying cnf.jkt was presented over DPoP, so
      # its insufficient_scope challenge is a DPoP challenge, not Bearer.
      opts = RequireScopes.init(["documents.write"])

      conn =
        %{"scope" => "documents.read", "cnf" => %{"jkt" => "abc123thumbprint"}}
        |> with_claims()
        |> RequireScopes.call(opts)

      assert conn.status == 403
      assert conn.halted

      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "DPoP ")
      assert challenge =~ ~s(error="insufficient_scope")
    end

    test "403 insufficient_scope when the claims carry no scope at all" do
      opts = RequireScopes.init(["documents.read"])

      conn =
        %{"sub" => "oc_abc123"}
        |> with_claims()
        |> RequireScopes.call(opts)

      assert conn.status == 403
      assert conn.halted
      assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
    end

    test "401 invalid_token when no claims were assigned (unauthenticated)" do
      opts = RequireScopes.init(["documents.read"])

      conn =
        conn(:get, "https://api.example.com/x")
        |> RequireScopes.call(opts)

      assert conn.status == 401
      assert conn.halted
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "403 insufficient_scope carries the RFC 9728 resource_metadata pointer when configured" do
      url = "https://api.example.com/.well-known/oauth-protected-resource"
      opts = RequireScopes.init(scopes: ["documents.write"], resource_metadata: url)

      conn =
        %{"scope" => "documents.read"}
        |> with_claims()
        |> RequireScopes.call(opts)

      assert conn.status == 403
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="#{url}")
    end

    test "401 invalid_token (unauthenticated) carries the resource_metadata pointer when configured" do
      url = "https://api.example.com/.well-known/oauth-protected-resource"
      opts = RequireScopes.init(scopes: ["documents.read"], resource_metadata: url)

      conn =
        conn(:get, "https://api.example.com/x")
        |> RequireScopes.call(opts)

      assert conn.status == 401
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="#{url}")
    end

    test "the resource_metadata pointer is omitted when not configured" do
      opts = RequireScopes.init(["documents.write"])

      conn =
        %{"scope" => "documents.read"}
        |> with_claims()
        |> RequireScopes.call(opts)

      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      refute challenge =~ "resource_metadata"
    end

    test "honours a custom :claims_key" do
      opts = RequireScopes.init(scopes: ["documents.read"], claims_key: :other_claims)

      conn =
        conn(:get, "https://api.example.com/x")
        |> Plug.Conn.assign(:other_claims, %{"scope" => "documents.read"})
        |> RequireScopes.call(opts)

      refute conn.halted
    end

    test "threads the :www_authenticate hook onto the 403 challenge" do
      inject = fn conn, challenge ->
        Plug.Conn.put_resp_header(
          conn,
          "www-authenticate",
          challenge <> ~s(, resource_metadata="https://rs.example/.well-known/oauth-protected-resource")
        )
      end

      opts = RequireScopes.init(scopes: ["documents.write"], www_authenticate: inject)

      conn =
        %{"scope" => "documents.read"}
        |> with_claims()
        |> RequireScopes.call(opts)

      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(error="insufficient_scope")
      assert challenge =~ ~s(resource_metadata="https://rs.example/.well-known/oauth-protected-resource")
    end

    test "threads the :send_error hook onto the 403 envelope" do
      send_error = fn conn, status, body ->
        conn
        |> Plug.Conn.put_resp_content_type("application/problem+json")
        |> Plug.Conn.send_resp(status, JSON.encode!(Map.put(body, "host_rendered", true)))
        |> Plug.Conn.halt()
      end

      opts = RequireScopes.init(scopes: ["documents.write"], send_error: send_error)

      conn =
        %{"scope" => "documents.read"}
        |> with_claims()
        |> RequireScopes.call(opts)

      assert conn.status == 403

      assert ["application/problem+json; charset=utf-8"] ==
               Plug.Conn.get_resp_header(conn, "content-type")

      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "insufficient_scope"
      assert body["host_rendered"] == true
    end

    test ":no_store hook is threaded onto the 403" do
      opts =
        RequireScopes.init(
          scopes: ["documents.write"],
          no_store: fn conn -> Plug.Conn.put_resp_header(conn, "x-no-store", "host") end
        )

      conn =
        %{"scope" => "documents.read"}
        |> with_claims()
        |> RequireScopes.call(opts)

      assert ["host"] == Plug.Conn.get_resp_header(conn, "x-no-store")
      assert [] == Plug.Conn.get_resp_header(conn, "pragma")
    end

    test "the :send_error hook is also threaded onto the 401 unauthenticated path" do
      send_error = fn conn, status, body ->
        conn
        |> Plug.Conn.put_resp_header("x-host-rendered", "true")
        |> Plug.Conn.send_resp(status, JSON.encode!(body))
        |> Plug.Conn.halt()
      end

      opts = RequireScopes.init(scopes: ["documents.read"], send_error: send_error)

      conn =
        conn(:get, "https://api.example.com/x")
        |> RequireScopes.call(opts)

      assert conn.status == 401
      assert ["true"] == Plug.Conn.get_resp_header(conn, "x-host-rendered")
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end
  end
end
