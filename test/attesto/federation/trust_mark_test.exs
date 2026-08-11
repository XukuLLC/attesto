defmodule Attesto.Federation.TrustMarkTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Federation.TrustMark
  alias Attesto.{JWS, Key, SigningAlg}
  alias Attesto.Test.Factory

  @tmi "https://trust-mark-issuer.example"
  @entity "https://entity.example"
  @mark_type "https://trust-mark-issuer.example/marks/certified"
  @now 1_800_000_000

  defp jwks(pem) do
    jwk = Key.jwk(pem)
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)

    %{
      "keys" => [
        Map.merge(public, %{"alg" => SigningAlg.infer(jwk), "kid" => Key.kid(pem)})
      ]
    }
  end

  defp trust_mark(pem, claims, header_overrides \\ %{}) do
    header = Map.merge(%{"alg" => "ES256", "kid" => Key.kid(pem), "typ" => "trust-mark+jwt"}, header_overrides)
    JWS.sign_compact(pem, header, claims)
  end

  defp claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => @tmi,
        "sub" => @entity,
        "trust_mark_type" => @mark_type,
        "iat" => @now - 10,
        "exp" => @now + 3600
      },
      overrides
    )
  end

  test "a validly-signed trust mark verifies" do
    pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims())

    assert {:ok, verified} = TrustMark.verify(jwt, jwks(pem), now: @now)
    assert verified["iss"] == @tmi
    assert verified["sub"] == @entity
    assert verified["trust_mark_type"] == @mark_type
  end

  test "the expected issuer/subject/trust_mark_type options are enforced" do
    pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims())

    assert {:ok, _} =
             TrustMark.verify(jwt, jwks(pem),
               now: @now,
               issuer: @tmi,
               subject: @entity,
               trust_mark_type: @mark_type
             )

    assert {:error, :invalid_trust_mark} =
             TrustMark.verify(jwt, jwks(pem), now: @now, issuer: "https://someone-else.example")

    assert {:error, :invalid_trust_mark} =
             TrustMark.verify(jwt, jwks(pem), now: @now, trust_mark_type: "https://other-mark.example")
  end

  test "a tampered trust mark is rejected" do
    pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims())

    # Flip the last character of the signature segment: same shape (still
    # valid base64url, same length), but the signature no longer verifies.
    [header, payload, signature] = String.split(jwt, ".")
    flipped = flip_last_char(signature)
    tampered = Enum.join([header, payload, flipped], ".")

    assert {:error, :invalid_signature} = TrustMark.verify(tampered, jwks(pem), now: @now)
  end

  defp flip_last_char(segment) do
    {rest, last} = String.split_at(segment, -1)
    replacement = if last == "A", do: "B", else: "A"
    rest <> replacement
  end

  test "a trust mark signed by the wrong key is rejected" do
    pem = Factory.ec_pem()
    wrong_pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims())

    assert {:error, :invalid_signature} = TrustMark.verify(jwt, jwks(wrong_pem), now: @now)
  end

  test "an expired trust mark is rejected" do
    pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims(%{"exp" => @now - 1}))

    assert {:error, :expired} = TrustMark.verify(jwt, jwks(pem), now: @now)
  end

  test "a trust mark with no exp at all is accepted (exp is OPTIONAL)" do
    pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims() |> Map.delete("exp"))

    assert {:ok, _} = TrustMark.verify(jwt, jwks(pem), now: @now)
  end

  test "rejects a token not typed trust-mark+jwt" do
    pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims(), %{"typ" => "JWT"})

    assert {:error, :invalid_typ} = TrustMark.verify(jwt, jwks(pem), now: @now)
  end

  test "rejects a missing trust_mark_type claim" do
    pem = Factory.ec_pem()
    jwt = trust_mark(pem, claims() |> Map.delete("trust_mark_type"))

    assert {:error, :invalid_trust_mark} = TrustMark.verify(jwt, jwks(pem), now: @now)
  end
end
