defmodule Attesto.Plug.AuthenticateTest do
  @moduledoc false
  # End-to-end plug tests: mint a real access token over Factory.config and
  # present it through the Authenticate plug, with the DPoP and mTLS
  # sender-constraint variants. Factory.config/2 installs a signing PEM into
  # the Attesto.Keystore.Static singleton via the global :attesto app env, so
  # the module runs serially.
  use ExUnit.Case, async: false

  import Plug.Test

  alias Attesto.DPoP
  alias Attesto.Plug.Authenticate
  alias Attesto.Test.Factory
  alias Attesto.Token

  @uri "https://api.example.com/x"

  defmodule ErrorTransport do
    @moduledoc false

    def send_error(conn, status, body) do
      conn
      |> Plug.Conn.put_resp_content_type("application/vnd.attesto-test+json")
      |> Plug.Conn.send_resp(status, JSON.encode!(%{"wrapped" => body}))
      |> Plug.Conn.halt()
    end
  end

  setup do
    pem = Factory.rsa_pem()
    {:ok, config: Factory.config(pem), pem: pem}
  end

  defp client_principal(overrides \\ %{}) do
    Map.merge(
      %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
      overrides
    )
  end

  defp request(headers) do
    Enum.reduce(headers, conn(:get, @uri), fn {k, v}, conn ->
      Plug.Conn.put_req_header(conn, k, v)
    end)
  end

  # A real DER-encoded self-signed X.509 root cert (OTP >= 24).
  defp cert_der(name \\ "cn=attesto-plug-test") do
    %{cert: der} = :public_key.pkix_test_root_cert(String.to_charlist(name), [])
    der
  end

  describe "Bearer access token" do
    test "a valid Bearer token authenticates and assigns the claims", %{config: config} do
      {:ok, %{access_token: token}} = Token.mint(config, client_principal())

      conn =
        [{"authorization", "Bearer " <> token}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config))

      refute conn.halted
      claims = conn.assigns.attesto_claims
      assert claims["sub"] == "oc_abc123"
      assert claims["principal_kind"] == "client"
    end

    test "honours a config function and a custom :claims_key", %{config: config} do
      {:ok, %{access_token: token}} = Token.mint(config, client_principal())

      conn =
        [{"authorization", "Bearer " <> token}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: fn -> config end, claims_key: :who))

      refute conn.halted
      assert conn.assigns.who["sub"] == "oc_abc123"
    end

    test "accepts a form-body access_token on POST when no Authorization header is present",
         %{config: config} do
      {:ok, %{access_token: token}} = Token.mint(config, client_principal())

      conn =
        :post
        |> conn(@uri, %{"access_token" => token})
        |> Authenticate.call(Authenticate.init(config: config))

      refute conn.halted
      assert conn.assigns.attesto_claims["sub"] == "oc_abc123"
    end

    test "accepts a host-provided fallback credential when no Authorization header is present",
         %{config: config} do
      {:ok, %{access_token: token}} = Token.mint(config, client_principal())

      conn =
        []
        |> request()
        |> Authenticate.call(
          Authenticate.init(
            config: config,
            credential_from_conn: fn _conn -> {:ok, :bearer, token} end
          )
        )

      refute conn.halted
      assert conn.assigns.attesto_claims["sub"] == "oc_abc123"
    end

    test "Authorization header takes precedence over a host-provided fallback credential",
         %{config: config} do
      {:ok, %{access_token: header_token}} = Token.mint(config, client_principal())
      {:ok, %{access_token: fallback_token}} = Token.mint(config, client_principal(%{sub: "oc_other"}))

      conn =
        [{"authorization", "Bearer " <> header_token}]
        |> request()
        |> Authenticate.call(
          Authenticate.init(
            config: config,
            credential_from_conn: fn _conn -> {:ok, :bearer, fallback_token} end
          )
        )

      refute conn.halted
      assert conn.assigns.attesto_claims["sub"] == "oc_abc123"
    end

    test "a missing Authorization header is 401 invalid_token with a Bearer challenge",
         %{config: config} do
      conn =
        []
        |> request()
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      assert conn.halted
      assert [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "Bearer ")
      assert challenge =~ ~s(error="invalid_token")
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "uses custom error transport while preserving the challenge", %{config: config} do
      conn =
        []
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, send_error: {ErrorTransport, :send_error}))

      assert conn.status == 401
      assert conn.halted
      assert [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "Bearer ")

      assert JSON.decode!(conn.resp_body) == %{
               "wrapped" => %{
                 "error" => "invalid_token",
                 "error_description" => "missing or malformed Authorization header"
               }
             }
    end

    test "a 401 carries the RFC 9728 resource_metadata pointer when configured", %{config: config} do
      url = "https://api.example.com/.well-known/oauth-protected-resource"

      conn =
        []
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, resource_metadata: url))

      assert conn.status == 401
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="#{url}")
    end

    test "a 401 omits the resource_metadata pointer when not configured", %{config: config} do
      conn =
        []
        |> request()
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      refute challenge =~ "resource_metadata"
    end

    test "a garbage Authorization header is 401 invalid_token", %{config: config} do
      conn =
        [{"authorization", "not-a-real-scheme zzz"}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "an expired token is 401 invalid_token", %{config: config} do
      past = System.system_time(:second) - 10_000
      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), now: past)

      conn =
        [{"authorization", "Bearer " <> token}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "a token signed by a foreign key is 401 invalid_token", %{config: config} do
      foreign_pem = Factory.rsa_pem()
      foreign_config = Factory.foreign_config(foreign_pem)
      {:ok, %{access_token: token}} = Token.mint(foreign_config, client_principal())

      conn =
        [{"authorization", "Bearer " <> token}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end
  end

  describe "DPoP-bound access token" do
    test "a matching proof + DPoP token authenticates", %{config: config} do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      jkt = JOSE.JWK.thumbprint(jwk)

      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), dpop_jkt: jkt)
      ath = DPoP.compute_ath(token)
      {proof, ^jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: @uri, ath: ath)

      conn =
        [{"authorization", "DPoP " <> token}, {"dpop", proof}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, replay_check: fn _jti, _ttl -> :ok end))

      refute conn.halted
      assert conn.assigns.attesto_claims["sub"] == "oc_abc123"
      assert conn.assigns.attesto_claims["cnf"]["jkt"] == jkt
    end

    test "a DPoP request is REFUSED when :replay_check is not wired (fail closed)", %{config: config} do
      # RFC 9449 §11.1: without a replay check a captured proof is replayable
      # within the iat window. The plug must not silently authenticate an
      # unprotected DPoP request - it fails closed so an unprotected DPoP
      # endpoint cannot ship. (This is the Mythos-review finding.)
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      jkt = JOSE.JWK.thumbprint(jwk)

      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), dpop_jkt: jkt)
      ath = DPoP.compute_ath(token)
      {proof, ^jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: @uri, ath: ath)

      conn =
        [{"authorization", "DPoP " <> token}, {"dpop", proof}]
        |> request()
        # No :replay_check, no acknowledgement.
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      assert conn.halted
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "DPoP ")
      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "invalid_dpop_proof"
      assert body["error_description"] == "replay_check_unconfigured"
    end

    test "dpop_replay_unprotected_acknowledged?: true lets DPoP through without :replay_check",
         %{config: config} do
      # The explicit opt-out for a host that knowingly accepts unprotected
      # DPoP (mirrors the cluster store's :multi_node_acknowledged?). Off by
      # default; only an explicit true allows it.
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      jkt = JOSE.JWK.thumbprint(jwk)

      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), dpop_jkt: jkt)
      ath = DPoP.compute_ath(token)
      {proof, ^jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: @uri, ath: ath)

      conn =
        [{"authorization", "DPoP " <> token}, {"dpop", proof}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, dpop_replay_unprotected_acknowledged?: true))

      refute conn.halted
      assert conn.assigns.attesto_claims["sub"] == "oc_abc123"
    end

    test "a proof bound to the wrong htu is 401 invalid_dpop_proof", %{config: config} do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      jkt = JOSE.JWK.thumbprint(jwk)

      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), dpop_jkt: jkt)
      ath = DPoP.compute_ath(token)

      {proof, ^jkt} =
        Factory.dpop_proof(jwk: jwk, htm: "GET", htu: "https://api.example.com/wrong", ath: ath)

      conn =
        [{"authorization", "DPoP " <> token}, {"dpop", proof}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, replay_check: fn _jti, _ttl -> :ok end))

      assert conn.status == 401
      assert [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "DPoP ")
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_dpop_proof"
    end

    test "a nonce_check demanding a nonce is 401 with a DPoP-Nonce header", %{config: config} do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      jkt = JOSE.JWK.thumbprint(jwk)

      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), dpop_jkt: jkt)
      ath = DPoP.compute_ath(token)
      {proof, ^jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: @uri, ath: ath)

      conn =
        [{"authorization", "DPoP " <> token}, {"dpop", proof}]
        |> request()
        |> Authenticate.call(
          Authenticate.init(
            config: config,
            replay_check: fn _jti, _ttl -> :ok end,
            nonce_check: fn _nonce -> {:error, :use_dpop_nonce} end,
            nonce_issue: fn -> "fresh-nonce-xyz" end
          )
        )

      assert conn.status == 401
      assert conn.halted
      assert ["fresh-nonce-xyz"] = Plug.Conn.get_resp_header(conn, "dpop-nonce")

      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "DPoP ")
      assert challenge =~ ~s(error="use_dpop_nonce")
    end

    test "a DPoP-bound token sent as Bearer with no proof gets a DPoP challenge", %{config: config} do
      # RFC 9449 §7.1: a binding failure on a cnf.jkt-bound token is
      # answered with a DPoP challenge so the client re-presents under the
      # DPoP scheme. The token verifier returns :dpop_proof_required; the
      # challenge scheme must be DPoP even though this request carried no
      # DPoP header (which would otherwise default the challenge to Bearer).
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      jkt = JOSE.JWK.thumbprint(jwk)

      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), dpop_jkt: jkt)

      conn =
        [{"authorization", "Bearer " <> token}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config))

      assert conn.status == 401
      assert conn.halted
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "DPoP ")
      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "invalid_token"
      assert body["error_description"] == "dpop_proof_required"
    end

    test "a DPoP header presented under the Bearer scheme is rejected, not ignored", %{config: config} do
      # RFC 9449 §7.1: a proof belongs to the DPoP auth scheme. A request
      # that ships a DPoP header while authorizing as Bearer is mixing
      # schemes; the proof binds nothing and must not be silently dropped.
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      jkt = JOSE.JWK.thumbprint(jwk)

      {:ok, %{access_token: token}} = Token.mint(config, client_principal(), dpop_jkt: jkt)
      ath = DPoP.compute_ath(token)
      {proof, ^jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: @uri, ath: ath)

      conn =
        [{"authorization", "Bearer " <> token}, {"dpop", proof}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, replay_check: fn _jti, _ttl -> :ok end))

      assert conn.status == 401
      assert conn.halted
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert String.starts_with?(challenge, "DPoP ")
      body = JSON.decode!(conn.resp_body)
      assert body["error"] == "invalid_dpop_proof"
      assert body["error_description"] == "dpop_scheme_required"
    end
  end

  describe "init/1 option validation" do
    test "a :nonce_check without a :nonce_issue raises at init", %{config: config} do
      # A use_dpop_nonce challenge is useless without a DPoP-Nonce header to
      # echo; fail at boot rather than emit a dead-end 401 at request time.
      assert_raise ArgumentError, ~r/nonce_check requires :nonce_issue/, fn ->
        Authenticate.init(config: config, nonce_check: fn _ -> {:error, :use_dpop_nonce} end)
      end
    end

    test "a :nonce_check paired with a :nonce_issue initializes cleanly", %{config: config} do
      opts = Authenticate.init(config: config, nonce_check: fn _ -> :ok end, nonce_issue: fn -> "n" end)
      assert Keyword.get(opts, :config) == config
    end
  end

  describe "mTLS-bound access token" do
    test "a matching client certificate authenticates", %{config: config} do
      der = cert_der()
      {:ok, thumb} = Attesto.MTLS.compute_thumbprint(der)

      {:ok, %{access_token: token}} =
        Token.mint(config, client_principal(), mtls_cert_thumbprint: thumb)

      conn =
        [{"authorization", "Bearer " <> token}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, cert_der: fn _conn -> der end))

      refute conn.halted
      assert conn.assigns.attesto_claims["sub"] == "oc_abc123"
      assert conn.assigns.attesto_claims["cnf"]["x5t#S256"] == thumb
    end

    test "the wrong client certificate is 401 invalid_token", %{config: config} do
      bound_der = cert_der("cn=attesto-plug-test-bound")
      {:ok, bound_thumb} = Attesto.MTLS.compute_thumbprint(bound_der)

      {:ok, %{access_token: token}} =
        Token.mint(config, client_principal(), mtls_cert_thumbprint: bound_thumb)

      other_der = cert_der("cn=attesto-plug-test-other")

      conn =
        [{"authorization", "Bearer " <> token}]
        |> request()
        |> Authenticate.call(Authenticate.init(config: config, cert_der: fn _conn -> other_der end))

      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end
  end
end
