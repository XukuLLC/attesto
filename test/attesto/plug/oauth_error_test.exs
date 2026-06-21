defmodule Attesto.Plug.OAuthErrorTest do
  @moduledoc false
  # Exercises the wire shape of the RFC 6750 / RFC 9449 error responses the
  # Attesto plugs render. Pure conn manipulation, no keystore or app env, so
  # the module is async-safe.
  use ExUnit.Case, async: true

  import Plug.Test

  alias Attesto.Plug.OAuthError

  defp www_authenticate(conn) do
    [value] = Plug.Conn.get_resp_header(conn, "www-authenticate")
    value
  end

  describe "unauthorized/4" do
    test "Bearer challenge: 401, names the scheme, carries error, halts, JSON body" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.unauthorized(:bearer, "invalid_token")

      assert conn.status == 401
      assert conn.halted

      challenge = www_authenticate(conn)
      assert String.starts_with?(challenge, "Bearer ")
      assert challenge =~ ~s(error="invalid_token")

      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "invalid_token"
    end

    test "DPoP scheme is named in the challenge" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.unauthorized(:dpop, "invalid_dpop_proof")

      challenge = www_authenticate(conn)
      assert String.starts_with?(challenge, "DPoP ")
      assert challenge =~ ~s(error="invalid_dpop_proof")
    end

    test ":description is echoed into the challenge and the JSON body" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.unauthorized(:bearer, "invalid_token", description: "token expired")

      assert www_authenticate(conn) =~ ~s(error_description="token expired")
      assert JSON.decode!(conn.resp_body)["error_description"] == "token expired"
    end

    test ":dpop_nonce sets a DPoP-Nonce response header (RFC 9449 §8)" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.unauthorized(:dpop, "use_dpop_nonce", dpop_nonce: "nonce-abc")

      assert conn.status == 401
      assert ["nonce-abc"] = Plug.Conn.get_resp_header(conn, "dpop-nonce")
      assert www_authenticate(conn) =~ ~s(error="use_dpop_nonce")
    end

    test "without :dpop_nonce no DPoP-Nonce header is set" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.unauthorized(:bearer, "invalid_token")

      assert [] == Plug.Conn.get_resp_header(conn, "dpop-nonce")
    end

    test ":resource_metadata is advertised as a quoted auth-param (RFC 9728 §5.1)" do
      url = "https://api.example.com/.well-known/oauth-protected-resource"

      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.unauthorized(:bearer, "invalid_token", resource_metadata: url)

      assert www_authenticate(conn) =~ ~s(resource_metadata="#{url}")
    end

    test "without :resource_metadata no resource_metadata auth-param is emitted" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.unauthorized(:bearer, "invalid_token")

      refute www_authenticate(conn) =~ "resource_metadata"
    end

    test "a non-https / malformed :resource_metadata is dropped (RFC 9728 §1.2)" do
      # The pointer must be an https metadata URL; a bad value is omitted rather
      # than rendered into an unusable challenge.
      for bad <- ["", "http://api.example/x", "https://api.example/%ZZ", "not-a-url", 123] do
        conn =
          conn(:get, "https://api.example.com/x")
          |> OAuthError.unauthorized(:bearer, "invalid_token", resource_metadata: bad)

        refute www_authenticate(conn) =~ "resource_metadata",
               "expected no resource_metadata for #{inspect(bad)}"
      end
    end
  end

  describe "insufficient_scope/2" do
    test "403, insufficient_scope error, scope auth-param naming the required scopes" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read", "positions.read"])

      assert conn.status == 403
      assert conn.halted

      challenge = www_authenticate(conn)
      assert String.starts_with?(challenge, "Bearer ")
      assert challenge =~ ~s(error="insufficient_scope")
      assert challenge =~ ~s(scope="documents.read positions.read")

      assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
    end

    test "defaults to the Bearer scheme but accepts DPoP" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"], :dpop)

      assert String.starts_with?(www_authenticate(conn), "DPoP ")
    end

    test ":resource_metadata is advertised on the 403 challenge (RFC 9728 §5.1)" do
      url = "https://api.example.com/.well-known/oauth-protected-resource"

      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"], :bearer, resource_metadata: url)

      assert www_authenticate(conn) =~ ~s(resource_metadata="#{url}")
    end

    test "without :resource_metadata the 403 challenge omits the auth-param" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"])

      refute www_authenticate(conn) =~ "resource_metadata"
    end

    test "default 403 sets the no-store cache headers and the error_description body" do
      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"])

      assert ["no-store"] == Plug.Conn.get_resp_header(conn, "cache-control")
      assert ["no-cache"] == Plug.Conn.get_resp_header(conn, "pragma")

      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "insufficient_scope"
      assert body["error_description"] == "requires scope: documents.read"
    end

    test ":no_store hook is honored on the 403 path" do
      no_store = fn conn -> Plug.Conn.put_resp_header(conn, "x-no-store", "host") end

      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"], :bearer, no_store: no_store)

      assert ["host"] == Plug.Conn.get_resp_header(conn, "x-no-store")
      # The host hook replaced core's default no-store path entirely: core's
      # `pragma: no-cache` (which nothing else sets) is absent.
      assert [] == Plug.Conn.get_resp_header(conn, "pragma")
    end

    test ":www_authenticate hook receives core's 403 challenge and can rewrite it" do
      # Mirrors the MCP resource server: a per-conn closure injects the RFC 9728
      # resource_metadata pointer onto the scope-rejection challenge.
      inject = fn conn, challenge ->
        Plug.Conn.put_resp_header(
          conn,
          "www-authenticate",
          challenge <> ~s(, resource_metadata="https://rs.example/.well-known/oauth-protected-resource")
        )
      end

      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"], :bearer, www_authenticate: inject)

      challenge = www_authenticate(conn)
      assert challenge =~ ~s(error="insufficient_scope")
      assert challenge =~ ~s(scope="documents.read")
      assert challenge =~ ~s(resource_metadata="https://rs.example/.well-known/oauth-protected-resource")
    end

    test ":send_error hook overrides the 403 response envelope" do
      send_error = fn conn, status, body ->
        conn
        |> Plug.Conn.put_resp_content_type("application/problem+json")
        |> Plug.Conn.send_resp(status, JSON.encode!(Map.put(body, "host_rendered", true)))
        |> Plug.Conn.halt()
      end

      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"], :bearer, send_error: send_error)

      assert conn.status == 403
      assert conn.halted

      assert ["application/problem+json; charset=utf-8"] ==
               Plug.Conn.get_resp_header(conn, "content-type")

      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "insufficient_scope"
      assert body["error_description"] == "requires scope: documents.read"
      assert body["host_rendered"] == true
    end

    test "all three transport hooks compose on one 403 (full delegation shape)" do
      parent = self()

      conn =
        conn(:get, "https://api.example.com/x")
        |> OAuthError.insufficient_scope(["documents.read"], :dpop,
          no_store: fn c ->
            send(parent, :no_store)
            c
          end,
          www_authenticate: fn c, challenge ->
            send(parent, {:wa, challenge})
            c
          end,
          send_error: fn c, status, body ->
            send(parent, {:se, status, body})
            Plug.Conn.halt(c)
          end
        )

      assert conn.halted
      assert_received :no_store
      assert_received {:wa, challenge}
      assert String.starts_with?(challenge, "DPoP ")
      assert_received {:se, 403, %{"error" => "insufficient_scope"}}
    end

    test "a non-https resource_metadata is dropped on the 403 path (RFC 9728 §3)" do
      # RFC 9728 requires an https metadata pointer; an http (incl. loopback) or
      # malformed value is omitted rather than advertised. A host that needs an
      # http loopback pointer in dev supplies the whole challenge via the
      # `:www_authenticate` hook instead.
      for bad <- [
            "http://localhost:9000/.well-known/oauth-protected-resource",
            "http://api.example.com/.well-known/oauth-protected-resource",
            "not-a-url"
          ] do
        conn =
          conn(:get, "https://api.example.com/x")
          |> OAuthError.insufficient_scope(["documents.read"], :bearer, resource_metadata: bad)

        refute www_authenticate(conn) =~ "resource_metadata",
               "expected no resource_metadata for #{inspect(bad)}"
      end
    end
  end
end
