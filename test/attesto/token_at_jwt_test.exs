defmodule Attesto.TokenAtJwtTest do
  @moduledoc false
  # RFC 9068 §2.1: an OAuth JWT access token SHOULD carry the JOSE header
  # `typ: "at+jwt"` so a resource server can tell it apart (by media type)
  # from an ID token or any other JWT. `Attesto.Token.mint/3` emits that
  # header for access tokens when `config.access_token_header_typ` is set
  # (default "at+jwt"); a refresh token carries none, and a host can set a
  # custom value or `nil`.
  #
  # Factory.config/2 installs the signing PEM into the global app env
  # (Attesto.Keystore.Static singleton), so these run serially.
  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Token

  setup do
    pem = Factory.rsa_pem()
    {:ok, pem: pem}
  end

  # The minted token's JOSE protected header. JOSE.JWS.peek_protected/1
  # returns the raw base64url-decoded protected-header JSON without
  # verifying the signature, which is exactly what we want to assert on.
  defp protected_header(jwt) when is_binary(jwt) do
    jwt
    |> JOSE.JWS.peek_protected()
    |> JSON.decode!()
  end

  defp client_principal do
    %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}}
  end

  describe "access-token JOSE header typ" do
    test "defaults to \"at+jwt\"", %{pem: pem} do
      config = Factory.config(pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      assert header["typ"] == "at+jwt"
    end

    test "the default RSA algorithm and kid are present on an access token", %{pem: pem} do
      config = Factory.config(pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
      assert header["kid"] != ""
    end

    test "a custom access_token_header_typ value appears verbatim", %{pem: pem} do
      config = Factory.config(pem, access_token_header_typ: "application/at+jwt")

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      assert header["typ"] == "application/at+jwt"
      # alg/kid are unaffected by the typ override.
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
    end

    test "access_token_header_typ: nil yields no \"typ\" header", %{pem: pem} do
      config = Factory.config(pem, access_token_header_typ: nil)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

      header = protected_header(jwt)
      refute Map.has_key?(header, "typ")
      # alg/kid are still present without a typ.
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
    end
  end

  describe "trusted key-bound signing algorithms" do
    for {alg, key} <- [
          {"RS256", :rsa},
          {"PS256", :rsa},
          {"ES256", {:ec, "P-256"}},
          {"ES384", {:ec, "P-384"}},
          {"ES512", {:ec, "P-521"}},
          {"EdDSA", :ed25519},
          {"Ed25519", :ed25519}
        ] do
      test "#{alg} mint, verify, and signed-claims inspection agree" do
        alg = unquote(alg)
        pem = signing_pem(unquote(Macro.escape(key)))
        config_opts = if alg in ["PS256", "Ed25519"], do: [signing_alg: alg], else: []
        config = Factory.config(pem, config_opts)

        assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())

        assert %{"alg" => ^alg, "kid" => kid} = protected_header(jwt)
        assert kid == Attesto.Key.kid(pem)

        assert {:ok, claims} = Token.verify(config, jwt)
        assert claims["sub"] == "oc_abc123"

        assert {:ok, signed_claims} = Token.peek_signed_claims(config, jwt)
        assert signed_claims == claims
      end
    end

    test "legacy EdDSA and explicit Ed448 access tokens mint and verify over Ed448" do
      enable_ed448_support()
      pem = Factory.ed448_pem()

      for alg <- ["EdDSA", "Ed448"] do
        config_opts = if alg == "Ed448", do: [signing_alg: alg], else: []
        config = Factory.config(pem, config_opts)

        assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal())
        assert %{"alg" => ^alg} = protected_header(jwt)
        assert {:ok, _claims} = Token.verify(config, jwt)
      end
    end

    test "verification does not learn algorithm policy from a valid token header" do
      pem = Factory.rsa_pem()
      rs256_config = Factory.config(pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(rs256_config, client_principal())

      assert protected_header(jwt) == %{
               "alg" => "RS256",
               "kid" => Attesto.Key.kid(pem),
               "typ" => "at+jwt"
             }

      ps256_config = Factory.config(pem, signing_alg: "PS256")

      assert {:error, :invalid_signature} = Token.verify(ps256_config, jwt)
      assert {:error, :invalid_signature} = Token.peek_signed_claims(ps256_config, jwt)
    end
  end

  describe "refresh-token JOSE header typ" do
    test ~s(a token minted with typ: "refresh" carries no "typ" header), %{pem: pem} do
      # The header typ tags access tokens specifically (RFC 9068). A
      # refresh token is not an OAuth JWT access token, so it gets no
      # header typ even when access_token_header_typ is set.
      config = Factory.config(pem)

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), typ: "refresh")

      header = protected_header(jwt)
      refute Map.has_key?(header, "typ")
      # alg/kid are always present, refresh included.
      assert header["alg"] == "RS256"
      assert is_binary(header["kid"])
    end

    test "a custom access_token_header_typ does not leak onto a refresh token", %{pem: pem} do
      config = Factory.config(pem, access_token_header_typ: "application/at+jwt")

      assert {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), typ: "refresh")

      header = protected_header(jwt)
      refute Map.has_key?(header, "typ")
    end
  end

  defp signing_pem(:rsa), do: Factory.rsa_pem()
  defp signing_pem({:ec, curve}), do: Factory.ec_pem(curve)
  defp signing_pem(:ed25519), do: Factory.ed_pem()

  defp enable_ed448_support do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
  end
end
