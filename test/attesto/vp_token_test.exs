defmodule Attesto.VpTokenTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{JWS, SdJwtVc, VpToken}

  defp keypair(spec \\ {:ec, "P-256"}) do
    jwk = JOSE.JWK.generate_key(spec)
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_kty, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp kb_jwt(holder_pem, presentation, nonce, audience, now, sd_hash \\ nil) do
    sd_hash = sd_hash || hash(presentation)

    JWS.sign_compact(holder_pem, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
      "nonce" => nonce,
      "aud" => audience,
      "iat" => now,
      "sd_hash" => sd_hash
    })
  end

  defp hash(value), do: :crypto.hash(:sha256, value) |> Base.url_encode64(padding: false)

  defp valid_context(opts \\ []) do
    {issuer_pem, issuer_jwk} = keypair()
    {holder_pem, holder_jwk} = keypair()
    now = 1_700_000_000

    vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: issuer_pem],
        claims: %{"given_name" => "Alice", "family_name" => "Example"},
        cnf: %{"jwk" => holder_jwk},
        iat: now
      )

    presentation = vc <> kb_jwt(holder_pem, vc, "nonce-1", "client-1", now)

    Map.merge(
      %{
        issuer_jwk: issuer_jwk,
        issuer_pem: issuer_pem,
        holder_pem: holder_pem,
        holder_jwk: holder_jwk,
        vc: vc,
        presentation: presentation,
        now: now,
        nonce: "nonce-1",
        audience: "client-1"
      },
      Map.new(opts)
    )
  end

  test "verifies a single credential and returns only safe fields" do
    ctx = valid_context()

    assert {:ok, %{"id" => result}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert result.vct == "identity"
    assert result.iss == "https://issuer.example"
    assert result.claims["given_name"] == "Alice"
    assert result.claims["family_name"] == "Example"
    assert result.cnf == %{"jwk" => ctx.holder_jwk}
    refute Map.has_key?(result, :issuer_jwt)
    refute Map.has_key?(result, :key_binding_jwt)
  end

  test "supports static issuer keys and an issuer resolver" do
    ctx = valid_context()
    caller = self()

    assert {:ok, %{"id" => _}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert {:ok, %{"id" => _}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               resolve_issuer: fn iss ->
                 send(caller, {:resolved_issuer, iss})
                 {:ok, ctx.issuer_jwk}
               end,
               now: ctx.now
             )

    assert_receive {:resolved_issuer, "https://issuer.example"}
  end

  test "rejects a wrong nonce and audience" do
    ctx = valid_context()

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: "wrong",
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: "wrong",
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  test "requires a Key Binding JWT" do
    ctx = valid_context()
    [jwt | _] = String.split(ctx.vc, "~")

    assert {:error, {"id", :missing_key_binding}} =
             VpToken.verify(%{"id" => jwt <> "~"},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  test "requires a holder key in cnf" do
    {issuer_pem, issuer_jwk} = keypair()
    {holder_pem, _holder_jwk} = keypair()
    now = 1_700_000_000

    vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: issuer_pem],
        claims: %{"given_name" => "Alice"},
        iat: now
      )

    presentation = vc <> kb_jwt(holder_pem, vc, "nonce-1", "client-1", now)

    assert {:error, {"id", :missing_holder_key}} =
             VpToken.verify(%{"id" => presentation},
               nonce: "nonce-1",
               audience: "client-1",
               issuer_jwks: issuer_jwk,
               now: now
             )
  end

  test "rejects a tampered signature and wrong issuer keys" do
    ctx = valid_context()
    tampered = tamper_signature(ctx.presentation)
    opts = [nonce: ctx.nonce, audience: ctx.audience, now: ctx.now]

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => tampered}, opts ++ [issuer_jwks: ctx.issuer_jwk])

    {_other_pem, wrong_jwk} = keypair()

    assert {:error, {"id", _reason}} =
             VpToken.verify(%{"id" => ctx.presentation}, opts ++ [issuer_jwks: wrong_jwk])
  end

  test "rejects an expired credential" do
    ctx = valid_context()

    expired_vc =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: ctx.issuer_pem],
        claims: %{"given_name" => "Alice"},
        cnf: %{"jwk" => ctx.holder_jwk},
        iat: ctx.now - 3600,
        exp: ctx.now - 3600
      )

    expired = expired_vc <> kb_jwt(ctx.holder_pem, expired_vc, ctx.nonce, ctx.audience, ctx.now)

    assert {:error, {"id", :expired}} =
             VpToken.verify(%{"id" => expired},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  test "preserves list-valued presentations" do
    ctx = valid_context()

    assert {:ok, %{"id" => results}} =
             VpToken.verify(%{"id" => [ctx.presentation, ctx.presentation]},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )

    assert is_list(results)
    assert length(results) == 2
    assert Enum.all?(results, &(&1.vct == "identity"))
  end

  test "checks expected query IDs before accepting the response" do
    ctx = valid_context()

    assert {:error, {:missing_credentials, ["missing"]}} =
             VpToken.verify(%{"id" => ctx.presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               expected_query_ids: ["id", "missing"],
               now: ctx.now
             )
  end

  test "rejects a Key Binding JWT whose sd_hash covers another presentation" do
    ctx = valid_context()
    wrong_kb = kb_jwt(ctx.holder_pem, ctx.presentation, ctx.nonce, ctx.audience, ctx.now, hash("other"))
    presentation = ctx.vc <> wrong_kb

    assert {:error, {"id", :invalid_key_binding}} =
             VpToken.verify(%{"id" => presentation},
               nonce: ctx.nonce,
               audience: ctx.audience,
               issuer_jwks: ctx.issuer_jwk,
               now: ctx.now
             )
  end

  describe "programmer errors" do
    test "requires a map and valid presentation values" do
      opts = [nonce: "nonce", audience: "client", issuer_jwks: %{}]

      assert_raise ArgumentError, fn -> VpToken.verify([], opts) end
      assert_raise ArgumentError, fn -> VpToken.verify(%{"id" => 123}, opts) end
      assert_raise ArgumentError, fn -> VpToken.verify(%{"id" => []}, opts) end
      assert_raise ArgumentError, fn -> VpToken.verify(%{"id" => [123]}, opts) end
    end

    test "requires the nonce and audience" do
      assert_raise ArgumentError, fn -> VpToken.verify(%{}, issuer_jwks: %{}, audience: "client") end
      assert_raise ArgumentError, fn -> VpToken.verify(%{}, issuer_jwks: %{}, nonce: "nonce") end
    end

    test "requires exactly one issuer trust source" do
      opts = [nonce: "nonce", audience: "client"]

      assert_raise ArgumentError, fn -> VpToken.verify(%{}, opts) end

      assert_raise ArgumentError, fn ->
        VpToken.verify(%{}, opts ++ [issuer_jwks: %{}, resolve_issuer: fn _iss -> {:ok, %{}} end])
      end
    end
  end

  defp tamper_signature(presentation) do
    [jwt | rest] = String.split(presentation, "~")
    [protected, payload, signature] = String.split(jwt, ".")
    replacement = if String.last(signature) == "A", do: "B", else: "A"
    tampered_jwt = Enum.join([protected, payload, String.slice(signature, 0..-2//1) <> replacement], ".")
    Enum.join([tampered_jwt | rest], "~")
  end
end
