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
  end
end
