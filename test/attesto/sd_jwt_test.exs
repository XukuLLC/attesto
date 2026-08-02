defmodule Attesto.SdJwtTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.SdJwt

  # {signing_pem, public_jwk_map} for an issuer or holder key.
  defp keypair(spec \\ {:ec, "P-256"}) do
    jwk = JOSE.JWK.generate_key(spec)
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_kty, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp b64(bytes), do: Base.url_encode64(bytes, padding: false)

  # Parse an issuance string into {jwt, [disclosures]} (drops the trailing "").
  defp parts(issuance) do
    [jwt | rest] = String.split(issuance, "~")
    {jwt, Enum.reject(rest, &(&1 == ""))}
  end

  # Build a presentation: keep the disclosures at `indexes`, append an optional
  # KB-JWT string.
  defp present(issuance, indexes, kb_jwt \\ nil) do
    {jwt, disclosures} = parts(issuance)
    kept = indexes |> Enum.map(&Enum.at(disclosures, &1))
    tail = if kb_jwt, do: [kb_jwt], else: [""]
    Enum.join([jwt | kept] ++ tail, "~")
  end

  defp sd_hash(issuance, indexes) do
    {jwt, disclosures} = parts(issuance)
    kept = indexes |> Enum.map(&Enum.at(disclosures, &1))
    to_hash = Enum.join([jwt | kept] ++ [""], "~")
    b64(:crypto.hash(:sha256, to_hash))
  end

  defp kb_jwt(holder_pem, claims) do
    Attesto.JWS.sign_compact(holder_pem, %{"alg" => "ES256", "typ" => "kb+jwt"}, claims)
  end

  describe "issue/2 + verify/3 round trip" do
    test "resolves every disclosed claim and strips the SD machinery" do
      {pem, jwk} = keypair()

      issuance =
        SdJwt.issue(
          %{"iss" => "https://issuer.example", "vct" => "demo", "given_name" => "Alice", "family_name" => "Example"},
          pem: pem,
          disclosable: ["given_name", "family_name"],
          typ: "vc+sd-jwt"
        )

      assert {:ok, %{claims: claims}} = SdJwt.verify(issuance, jwk)

      assert claims["given_name"] == "Alice"
      assert claims["family_name"] == "Example"
      assert claims["iss"] == "https://issuer.example"
      refute Map.has_key?(claims, "_sd")
      refute Map.has_key?(claims, "_sd_alg")
    end

    test "a selective presentation reveals only the presented disclosures" do
      {pem, jwk} = keypair()

      issuance =
        SdJwt.issue(%{"iss" => "iss", "given_name" => "Alice", "family_name" => "Example"},
          pem: pem,
          disclosable: ["given_name", "family_name"]
        )

      # Present only the first disclosure (order is issuance order).
      presentation = present(issuance, [0])

      assert {:ok, %{claims: claims}} = SdJwt.verify(presentation, jwk)
      # Exactly one of the two disclosable claims is present.
      revealed = Map.take(claims, ["given_name", "family_name"])
      assert map_size(revealed) == 1
    end
  end

  describe "verify/3 rejections (spec §7.3)" do
    test "a presented disclosure not referenced by any digest is rejected" do
      {pem, jwk} = keypair()
      {other_pem, _} = keypair()

      issuance = SdJwt.issue(%{"iss" => "iss", "x" => 1}, pem: pem, disclosable: ["x"])

      # A foreign disclosure from a DIFFERENT SD-JWT: its digest is not in `_sd`.
      foreign = SdJwt.issue(%{"iss" => "iss", "y" => 2}, pem: other_pem, disclosable: ["y"])
      {_jwt, [foreign_disclosure]} = parts(foreign)

      {jwt, [own_disclosure]} = parts(issuance)
      tampered = Enum.join([jwt, own_disclosure, foreign_disclosure, ""], "~")

      assert {:error, :unused_disclosure} = SdJwt.verify(tampered, jwk)
    end

    test "a bad issuer signature is rejected" do
      {pem, _jwk} = keypair()
      {_other_pem, wrong_jwk} = keypair()

      issuance = SdJwt.issue(%{"iss" => "iss", "x" => 1}, pem: pem, disclosable: ["x"])

      assert {:error, :invalid_signature} = SdJwt.verify(issuance, wrong_jwk)
    end

    test "a duplicated presented disclosure is rejected" do
      {pem, jwk} = keypair()
      issuance = SdJwt.issue(%{"iss" => "iss", "x" => 1}, pem: pem, disclosable: ["x"])
      {jwt, [disclosure]} = parts(issuance)
      doubled = Enum.join([jwt, disclosure, disclosure, ""], "~")

      assert {:error, :duplicate_digest} = SdJwt.verify(doubled, jwk)
    end

    test "a malformed wire form is rejected" do
      {_pem, jwk} = keypair()
      assert {:error, :malformed} = SdJwt.verify("not-an-sd-jwt", jwk)
    end
  end

  describe "verify_key_binding/3" do
    setup do
      {issuer_pem, issuer_jwk} = keypair()
      {holder_pem, holder_jwk} = keypair()

      issuance =
        SdJwt.issue(
          %{"iss" => "iss", "given_name" => "Alice", "cnf" => %{"jwk" => holder_jwk}},
          pem: issuer_pem,
          disclosable: ["given_name"]
        )

      %{issuer_jwk: issuer_jwk, holder_pem: holder_pem, holder_jwk: holder_jwk, issuance: issuance}
    end

    test "accepts a correct holder key binding", ctx do
      now = System.system_time(:second)

      kb =
        kb_jwt(ctx.holder_pem, %{
          "nonce" => "n-123",
          "aud" => "https://verifier.example",
          "iat" => now,
          "sd_hash" => sd_hash(ctx.issuance, [0])
        })

      presentation = present(ctx.issuance, [0], kb)

      assert {:ok, verified} = SdJwt.verify(presentation, ctx.issuer_jwk)

      assert :ok =
               SdJwt.verify_key_binding(verified, ctx.holder_jwk,
                 nonce: "n-123",
                 audience: "https://verifier.example",
                 now: now
               )
    end

    test "rejects a wrong nonce, wrong audience, and a mismatched sd_hash", ctx do
      now = System.system_time(:second)

      good_kb =
        kb_jwt(ctx.holder_pem, %{
          "nonce" => "n-123",
          "aud" => "https://verifier.example",
          "iat" => now,
          "sd_hash" => sd_hash(ctx.issuance, [0])
        })

      {:ok, verified} = SdJwt.verify(present(ctx.issuance, [0], good_kb), ctx.issuer_jwk)

      assert {:error, :invalid_key_binding} =
               SdJwt.verify_key_binding(verified, ctx.holder_jwk,
                 nonce: "WRONG",
                 audience: "https://verifier.example",
                 now: now
               )

      assert {:error, :invalid_key_binding} =
               SdJwt.verify_key_binding(verified, ctx.holder_jwk,
                 nonce: "n-123",
                 audience: "https://attacker.example",
                 now: now
               )

      # sd_hash computed over a DIFFERENT disclosure set than presented.
      wrong_hash_kb =
        kb_jwt(ctx.holder_pem, %{
          "nonce" => "n-123",
          "aud" => "https://verifier.example",
          "iat" => now,
          "sd_hash" => b64(:crypto.hash(:sha256, "something-else"))
        })

      {:ok, verified2} = SdJwt.verify(present(ctx.issuance, [0], wrong_hash_kb), ctx.issuer_jwk)

      assert {:error, :invalid_key_binding} =
               SdJwt.verify_key_binding(verified2, ctx.holder_jwk,
                 nonce: "n-123",
                 audience: "https://verifier.example",
                 now: now
               )
    end

    test "rejects a key binding signed by the wrong holder key", ctx do
      {attacker_pem, _} = keypair()
      now = System.system_time(:second)

      kb =
        kb_jwt(attacker_pem, %{
          "nonce" => "n-123",
          "aud" => "https://verifier.example",
          "iat" => now,
          "sd_hash" => sd_hash(ctx.issuance, [0])
        })

      {:ok, verified} = SdJwt.verify(present(ctx.issuance, [0], kb), ctx.issuer_jwk)

      assert {:error, :invalid_key_binding} =
               SdJwt.verify_key_binding(verified, ctx.holder_jwk,
                 nonce: "n-123",
                 audience: "https://verifier.example",
                 now: now
               )
    end
  end
end
