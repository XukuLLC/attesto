defmodule Attesto.KeyAttestationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.KeyAttestation

  @now 1_659_145_924

  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_map(key) do
    {_, map} = JOSE.JWK.to_public_map(key)
    map
  end

  defp sign(key, header, claims) do
    {_header, compact} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp key_attestation(signer, attested_keys, overrides \\ %{}) do
    header = %{"alg" => "ES256", "typ" => "key-attestation+jwt", "kid" => "ks-1"}

    claims =
      Map.merge(
        %{
          "iss" => "https://key-storage.example",
          "iat" => @now,
          "exp" => @now + 86_400,
          "attested_keys" => attested_keys
        },
        overrides
      )

    sign(signer, header, claims)
  end

  defp trusted(signer), do: %{"keys" => [Map.put(public_map(signer), "kid", "ks-1")]}

  test "verifies a valid key attestation and returns its attested_keys" do
    signer = ec_key()
    attested = ec_key()

    jwt = key_attestation(signer, [public_map(attested)], %{"key_storage" => ["iso_18045_moderate"]})

    assert {:ok, result} = KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now)
    assert result.attested_keys == [public_map(attested)]
    assert result.key_storage == ["iso_18045_moderate"]
    assert result.claims["iss"] == "https://key-storage.example"
  end

  test "rejects an attestation signed by an untrusted key" do
    signer = ec_key()
    impostor = ec_key()
    attested = ec_key()

    jwt = key_attestation(impostor, [public_map(attested)])

    assert {:error, :invalid_signature} = KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now)
  end

  test "rejects an expired attestation" do
    signer = ec_key()
    attested = ec_key()

    jwt = key_attestation(signer, [public_map(attested)], %{"exp" => @now - 1})

    assert {:error, :expired} = KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now)
  end

  test "requires exp by default but allows opting out" do
    signer = ec_key()
    attested = ec_key()

    jwt =
      %{"iss" => "https://key-storage.example", "iat" => @now, "attested_keys" => [public_map(attested)]}
      |> then(&sign(signer, %{"alg" => "ES256", "typ" => "key-attestation+jwt", "kid" => "ks-1"}, &1))

    assert {:error, :missing_exp} = KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now)

    assert {:ok, _result} =
             KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now, require_exp: false)
  end

  test "rejects malformed security booleans before parsing or verification" do
    for key <- [:require_exp, :enforce_fapi_alg_policy],
        invalid <- [nil, 0, "false", []] do
      assert_raise ArgumentError, ~r/^:#{key} must be true or false$/, fn ->
        KeyAttestation.verify("not-a-jwt", [{key, invalid}])
      end
    end
  end

  test "rejects a missing or empty attested_keys" do
    signer = ec_key()

    jwt = key_attestation(signer, [])
    assert {:error, :missing_attested_keys} = KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now)

    jwt_no_keys =
      %{"iss" => "https://key-storage.example", "iat" => @now, "exp" => @now + 60}
      |> then(&sign(signer, %{"alg" => "ES256", "typ" => "key-attestation+jwt", "kid" => "ks-1"}, &1))

    assert {:error, :missing_attested_keys} =
             KeyAttestation.verify(jwt_no_keys, trusted_jwks: trusted(signer), now: @now)
  end

  test "rejects an attested key that carries private material" do
    signer = ec_key()
    attested = ec_key()
    leaky = Map.put(public_map(attested), "d", "leaked")

    jwt = key_attestation(signer, [leaky])

    assert {:error, :invalid_attested_keys} = KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now)
  end

  test "matches an expected nonce and rejects a mismatched one" do
    signer = ec_key()
    attested = ec_key()

    good = key_attestation(signer, [public_map(attested)], %{"nonce" => "c-nonce-1"})
    bad = key_attestation(signer, [public_map(attested)], %{"nonce" => "c-nonce-wrong"})

    opts = [trusted_jwks: trusted(signer), now: @now, nonce: "c-nonce-1"]

    assert {:ok, _} = KeyAttestation.verify(good, opts)
    assert {:error, :invalid_nonce} = KeyAttestation.verify(bad, opts)
  end

  test "rejects the wrong typ header" do
    signer = ec_key()
    attested = ec_key()

    header = %{"alg" => "ES256", "typ" => "openid4vci-proof+jwt", "kid" => "ks-1"}
    claims = %{"iat" => @now, "exp" => @now + 60, "attested_keys" => [public_map(attested)]}
    jwt = sign(signer, header, claims)

    assert {:error, :invalid_typ} = KeyAttestation.verify(jwt, trusted_jwks: trusted(signer), now: @now)
  end

  describe "covers_key?/2" do
    test "true iff the key's thumbprint is among attested_keys" do
      attested = ec_key()
      other = ec_key()
      attested_map = public_map(attested)

      assert KeyAttestation.covers_key?([attested_map], attested_map)
      refute KeyAttestation.covers_key?([attested_map], public_map(other))
      refute KeyAttestation.covers_key?([], attested_map)
    end

    test "matches regardless of member order or extra non-canonical fields" do
      attested = ec_key()
      canonical = public_map(attested)
      reordered = canonical |> Map.to_list() |> Enum.reverse() |> Map.new()

      assert KeyAttestation.covers_key?([reordered], canonical)
    end
  end
end
