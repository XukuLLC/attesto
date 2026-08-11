defmodule Attesto.SdJwtVcTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.{SdJwt, SdJwtVc, StatusList}

  defp keypair(spec \\ {:ec, "P-256"}) do
    jwk = JOSE.JWK.generate_key(spec)
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_kty, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  describe "issue/2 + verify/3" do
    test "issues a typed credential and reconstructs its claims" do
      {pem, jwk} = keypair()

      vc =
        SdJwtVc.issue(
          [iss: "https://issuer.example", vct: "https://credentials.example/identity", pem: pem],
          claims: %{"given_name" => "Alice", "family_name" => "Example", "birthdate" => "1990-01-01"},
          exp: System.system_time(:second) + 3600
        )

      assert {:ok, verified} = SdJwtVc.verify(vc, jwk)
      assert verified.iss == "https://issuer.example"
      assert verified.vct == "https://credentials.example/identity"
      assert verified.claims["given_name"] == "Alice"
      assert verified.claims["birthdate"] == "1990-01-01"
    end

    test "all subject claims are selectively disclosable by default" do
      {pem, jwk} = keypair()

      vc =
        SdJwtVc.issue([iss: "iss", vct: "t", pem: pem], claims: %{"a" => 1, "b" => 2})

      # Nothing disclosed: the subject claims are hidden, registered ones remain.
      [jwt | _] = String.split(vc, "~")
      bare = jwt <> "~"

      assert {:ok, verified} = SdJwtVc.verify(bare, jwk)
      assert verified.claims["iss"] == "iss"
      refute Map.has_key?(verified.claims, "a")
      refute Map.has_key?(verified.claims, "b")
    end

    test "an atom-keyed subject-claim collision cannot corrupt the registered cnf" do
      {pem, jwk} = keypair()
      holder = %{"kty" => "EC", "crv" => "P-256", "x" => "abc", "y" => "def"}

      # A caller passes an atom-keyed `:cnf` in :claims that collides with the
      # real string `"cnf"` registered claim. Without string-keying, both would
      # survive Map.merge as separate keys -> a duplicate JSON member.
      vc =
        SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem],
          claims: %{"given_name" => "Alice", cnf: "attacker-atom"},
          cnf: %{"jwk" => holder}
        )

      [jwt | _] = String.split(vc, "~")
      assert {:ok, verified} = SdJwtVc.verify(jwt <> "~", jwk)
      # cnf is the real holder key, unambiguously (no duplicate member).
      assert verified.cnf == %{"jwk" => holder}
      # The raw payload has exactly one "cnf" member.
      {:ok, payload} = Attesto.JWS.peek_json(jwt, :payload)
      assert payload["cnf"] == %{"jwk" => holder}
    end

    test "carries an always-visible Token Status List reference" do
      {pem, jwk} = keypair()
      uri = "https://issuer/statuslists/1"

      vc =
        SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem],
          claims: %{"given_name" => "Alice"},
          status: StatusList.reference(uri, 42)
        )

      [jwt | _disclosures] = String.split(vc, "~")

      assert {:ok, verified} = SdJwtVc.verify(jwt <> "~", jwk)

      assert verified.claims["status"] == %{
               "status_list" => %{"idx" => 42, "uri" => uri}
             }

      refute Map.has_key?(verified.claims, "given_name")
    end

    test "registered claims can never be made selectively disclosable" do
      {pem, jwk} = keypair()
      {_holder_pem, holder_jwk} = keypair()
      uri = "https://issuer/statuslists/1"

      vc =
        SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem],
          claims: %{"given_name" => "Alice"},
          cnf: %{"jwk" => holder_jwk},
          status: StatusList.reference(uri, 1),
          # Attempt to strip holder-binding and status by listing them
          # (and a registered claim not even present, "sub") alongside a
          # real subject claim.
          disclosable: ["given_name", "cnf", "status", "sub"]
        )

      # No Disclosure was minted for cnf/status at all - they cannot be
      # stripped by a holder because there is nothing to omit.
      [_jwt | disclosures] = vc |> String.split("~") |> Enum.reject(&(&1 == ""))

      disclosed_names =
        Enum.map(disclosures, fn d ->
          [_salt, name, _value] = d |> Base.url_decode64!(padding: false) |> JSON.decode!()
          name
        end)

      assert disclosed_names == ["given_name"]

      # A holder presenting zero disclosures still gets cnf/status in the
      # clear: they were never behind an `_sd` digest to omit.
      [jwt | _] = String.split(vc, "~")
      assert {:ok, bare} = SdJwtVc.verify(jwt <> "~", jwk)
      assert bare.claims["cnf"] == %{"jwk" => holder_jwk}
      assert bare.claims["status"] == %{"status_list" => %{"idx" => 1, "uri" => uri}}
      refute Map.has_key?(bare.claims, "given_name")

      # The normal subject claim IS disclosable, proving the reject only
      # excludes registered names rather than disabling disclosure entirely.
      assert {:ok, full} = SdJwtVc.verify(vc, jwk)
      assert full.claims["given_name"] == "Alice"
    end

    test "rejects a non-map status option" do
      {pem, _jwk} = keypair()

      assert_raise ArgumentError, ":status must be a map; got \"invalid\"", fn ->
        SdJwtVc.issue([iss: "i", vct: "t", pem: pem], status: "invalid")
      end
    end
  end

  describe "verify/3 VC claim rules" do
    test "rejects a plain SD-JWT that is not typed as a VC" do
      {pem, jwk} = keypair()
      # A base SD-JWT with no vc+sd-jwt typ.
      sd_jwt = SdJwt.issue(%{"iss" => "iss", "vct" => "t", "x" => 1}, pem: pem, disclosable: ["x"])

      assert {:error, :invalid_typ} = SdJwtVc.verify(sd_jwt, jwk)
    end

    test "rejects a credential missing vct" do
      {pem, jwk} = keypair()
      # Typed vc+sd-jwt but no vct claim.
      no_vct = SdJwt.issue(%{"iss" => "iss", "x" => 1}, pem: pem, disclosable: ["x"], typ: "vc+sd-jwt")

      assert {:error, :missing_vct} = SdJwtVc.verify(no_vct, jwk)
    end

    test "rejects an expired credential and one not yet valid" do
      {pem, jwk} = keypair()
      now = System.system_time(:second)

      expired = SdJwtVc.issue([iss: "i", vct: "t", pem: pem], exp: now - 3600)
      assert {:error, :expired} = SdJwtVc.verify(expired, jwk, now: now)

      future = SdJwtVc.issue([iss: "i", vct: "t", pem: pem], nbf: now + 3600)
      assert {:error, :not_yet_valid} = SdJwtVc.verify(future, jwk, now: now)
    end

    test "keeps the 60-second expiry and not-before leeway boundaries" do
      {pem, jwk} = keypair()
      now = 1_700_000_000

      accepted_exp = SdJwtVc.issue([iss: "i", vct: "t", pem: pem], exp: now - 30, iat: now)
      assert {:ok, _} = SdJwtVc.verify(accepted_exp, jwk, now: now)

      rejected_exp = SdJwtVc.issue([iss: "i", vct: "t", pem: pem], exp: now - 61, iat: now)
      assert {:error, :expired} = SdJwtVc.verify(rejected_exp, jwk, now: now)

      accepted_nbf = SdJwtVc.issue([iss: "i", vct: "t", pem: pem], nbf: now + 60, iat: now)
      assert {:ok, _} = SdJwtVc.verify(accepted_nbf, jwk, now: now)

      rejected_nbf = SdJwtVc.issue([iss: "i", vct: "t", pem: pem], nbf: now + 61, iat: now)
      assert {:error, :not_yet_valid} = SdJwtVc.verify(rejected_nbf, jwk, now: now)
    end
  end

  test "holder key binding verifies against the credential's cnf key" do
    {issuer_pem, issuer_jwk} = keypair()
    {holder_pem, holder_jwk} = keypair()
    now = System.system_time(:second)

    vc =
      SdJwtVc.issue([iss: "i", vct: "t", pem: issuer_pem],
        claims: %{"given_name" => "Alice"},
        cnf: %{"jwk" => holder_jwk}
      )

    # Holder presents (no disclosures selected here) with a KB-JWT.
    [jwt | _] = String.split(vc, "~")
    sd_hash = :crypto.hash(:sha256, jwt <> "~") |> Base.url_encode64(padding: false)

    kb =
      Attesto.JWS.sign_compact(holder_pem, %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
        "nonce" => "n-1",
        "aud" => "https://verifier.example",
        "iat" => now,
        "sd_hash" => sd_hash
      })

    presentation = jwt <> "~" <> kb

    assert {:ok, verified} = SdJwtVc.verify(presentation, issuer_jwk, now: now)
    assert %{"jwk" => ^holder_jwk} = verified.cnf

    assert :ok =
             SdJwt.verify_key_binding(verified, verified.cnf["jwk"],
               nonce: "n-1",
               audience: "https://verifier.example",
               now: now
             )
  end
end
