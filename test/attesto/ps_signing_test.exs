defmodule Attesto.PSSigningTest do
  @moduledoc false
  # Uses Attesto.Keystore.Static app env, so these run serially.
  use ExUnit.Case, async: false

  alias Attesto.Config
  alias Attesto.IDToken
  alias Attesto.Key
  alias Attesto.Keystore.Static
  alias Attesto.PrincipalKind
  alias Attesto.Test.Factory
  alias Attesto.Token

  @client_id "attesto-fapi-dpop-client"
  @subject "usr_alice"

  setup do
    pem = Factory.rsa_pem()
    kid = Key.kid(pem)

    Application.put_env(:attesto, Static,
      signing_pem: pem,
      signing_alg: "PS256",
      key_algs: %{kid => "PS256"}
    )

    on_exit(fn -> Application.delete_env(:attesto, Static) end)

    config =
      Config.new(
        issuer: "https://oidc.example.test",
        audience: "https://api.example.test",
        keystore: Static,
        principal_kinds: [
          PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}]),
          PrincipalKind.new("user", "usr_")
        ]
      )

    {:ok, config: config, pem: pem}
  end

  test "ID Tokens signed as PS256 use the RFC 7518 salt length", %{config: config, pem: pem} do
    assert {:ok, jwt} = IDToken.mint(config, @subject, @client_id, nonce: "n-1")

    assert protected_header(jwt)["alg"] == "PS256"
    assert_ps256_rfc7518_signature(jwt, pem)
    assert {:ok, _claims} = IDToken.verify(config, jwt, client_id: @client_id)
  end

  test "access tokens signed as PS256 use the RFC 7518 salt length", %{config: config, pem: pem} do
    principal = %{
      kind: "client",
      sub: "oc_fapi_client",
      scopes: ["openid"],
      claims: %{"client_id" => "oc_fapi_client"}
    }

    assert {:ok, %{access_token: jwt}} = Token.mint(config, principal)

    assert protected_header(jwt)["alg"] == "PS256"
    assert_ps256_rfc7518_signature(jwt, pem)
    assert {:ok, _claims} = Token.verify(config, jwt)
  end

  test "PS256 configured via signing_alg alone (no key_algs) still verifies its own tokens" do
    pem = Factory.rsa_pem()

    # signing_alg set, key_algs DELIBERATELY omitted. Before the Static keystore
    # labelled the signing key from signing_alg, verify inferred RS256 from the
    # RSA key and rejected the server's own PS256 tokens as :invalid_signature.
    Application.put_env(:attesto, Static, signing_pem: pem, signing_alg: "PS256")
    on_exit(fn -> Application.delete_env(:attesto, Static) end)

    config =
      Config.new(
        issuer: "https://oidc.example.test",
        audience: "https://api.example.test",
        keystore: Static,
        principal_kinds: [
          PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
        ]
      )

    principal = %{
      kind: "client",
      sub: "oc_fapi_client",
      scopes: ["openid"],
      claims: %{"client_id" => "oc_fapi_client"}
    }

    assert {:ok, %{access_token: jwt}} = Token.mint(config, principal)
    assert protected_header(jwt)["alg"] == "PS256"
    assert {:ok, _claims} = Token.verify(config, jwt)
  end

  defp protected_header(jwt) do
    jwt
    |> JOSE.JWS.peek_protected()
    |> JSON.decode!()
  end

  defp assert_ps256_rfc7518_signature(jwt, pem) do
    [header, payload, signature] = String.split(jwt, ".")
    signing_input = header <> "." <> payload

    assert :public_key.verify(
             signing_input,
             :sha256,
             Base.url_decode64!(signature, padding: false),
             public_key(pem),
             rsa_pss_sha256_opts()
           )
  end

  defp public_key(pem) do
    pem
    |> :public_key.pem_decode()
    |> List.first()
    |> :public_key.pem_entry_decode()
  end

  defp rsa_pss_sha256_opts do
    [
      {:rsa_padding, :rsa_pkcs1_pss_padding},
      {:rsa_pss_saltlen, 32}
    ]
  end
end
