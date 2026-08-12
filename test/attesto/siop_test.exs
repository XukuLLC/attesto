defmodule Attesto.SiopTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Bitwise

  alias Attesto.{Siop, Thumbprint}

  @base58_alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  @audience "https://rp.example/client"
  @nonce "siop-request-nonce"
  @now 1_800_000_000
  @self_issued_issuer "https://self-issued.me/v2"

  setup do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    jwk = public_map(key)
    {:ok, subject} = Thumbprint.of_jwk(jwk)

    claims = %{
      "iss" => @self_issued_issuer,
      "sub" => subject,
      "aud" => @audience,
      "nonce" => @nonce,
      "exp" => @now + 300,
      "iat" => @now - 1,
      "sub_jwk" => jwk
    }

    %{key: key, jwk: jwk, subject: subject, claims: claims}
  end

  test "verifies a self-signed P-256 ID Token and returns subject plus holder key", context do
    token = sign(context.key, context.claims)

    assert {:ok, %{subject: context.subject, jwk: context.jwk}} ==
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "accepts iss equal to sub", context do
    claims = Map.put(context.claims, "iss", context.subject)
    token = sign(context.key, claims)

    assert {:ok, %{subject: context.subject, jwk: context.jwk}} ==
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "accepts sub_jwk in the protected header", context do
    claims = Map.delete(context.claims, "sub_jwk")
    token = sign(context.key, claims, %{"sub_jwk" => context.jwk})

    assert {:ok, %{subject: context.subject, jwk: context.jwk}} ==
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "verifies a did:jwk subject through its fixed #0 verification method", context do
    subject = did_jwk(context.jwk)
    expected_jwk = context.jwk

    claims =
      context.claims
      |> Map.delete("sub_jwk")
      |> Map.put("iss", subject)
      |> Map.put("sub", subject)

    token = sign(context.key, claims, %{"kid" => subject <> "#0"})

    assert {:ok, %{subject: ^subject, jwk: ^expected_jwk}} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "verifies a did:key subject through its fingerprint verification method", context do
    subject = did_key(context.jwk)
    fingerprint = String.replace_prefix(subject, "did:key:", "")
    expected_jwk = context.jwk

    claims =
      context.claims
      |> Map.delete("sub_jwk")
      |> Map.put("iss", subject)
      |> Map.put("sub", subject)

    token = sign(context.key, claims, %{"kid" => subject <> "#" <> fingerprint})

    assert {:ok, %{subject: ^subject, jwk: ^expected_jwk}} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "verifies an Ed25519 did:key subject", context do
    key = JOSE.JWK.generate_key({:okp, :Ed25519})
    jwk = public_map(key)
    subject = did_key(jwk)
    fingerprint = String.replace_prefix(subject, "did:key:", "")

    claims =
      context.claims
      |> Map.delete("sub_jwk")
      |> Map.put("iss", subject)
      |> Map.put("sub", subject)

    token = sign(key, claims, %{"alg" => "EdDSA", "kid" => subject <> "#" <> fingerprint})

    assert {:ok, %{subject: ^subject, jwk: ^jwk}} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "DID subjects require their exact protected verification-method kid", context do
    subject = did_jwk(context.jwk)

    claims =
      context.claims
      |> Map.delete("sub_jwk")
      |> Map.put("iss", subject)
      |> Map.put("sub", subject)

    for header <- [%{}, %{"kid" => subject}, %{"kid" => subject <> "#other"}] do
      token = sign(context.key, claims, header)

      assert {:error, :invalid_subject} =
               Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
    end
  end

  test "DID subjects reject sub_jwk in either the payload or protected header", context do
    subject = did_jwk(context.jwk)
    base_claims = context.claims |> Map.put("iss", subject) |> Map.put("sub", subject)
    kid = subject <> "#0"

    payload_token = sign(context.key, base_claims, %{"kid" => kid})

    header_token =
      context.key
      |> sign(Map.delete(base_claims, "sub_jwk"), %{"kid" => kid, "sub_jwk" => context.jwk})

    for token <- [payload_token, header_token] do
      assert {:error, :invalid_sub_jwk} =
               Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
    end
  end

  test "DID subjects require iss equal to sub", context do
    subject = did_jwk(context.jwk)

    claims =
      context.claims
      |> Map.delete("sub_jwk")
      |> Map.put("iss", @self_issued_issuer)
      |> Map.put("sub", subject)

    token = sign(context.key, claims, %{"kid" => subject <> "#0"})

    assert {:error, :invalid_issuer} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "DID subjects fail closed for unsupported methods and mismatched signing keys", context do
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    subject = did_jwk(public_map(other))

    claims =
      context.claims
      |> Map.delete("sub_jwk")
      |> Map.put("iss", subject)
      |> Map.put("sub", subject)

    wrong_key_token = sign(context.key, claims, %{"kid" => subject <> "#0"})

    unsupported_subject = "did:web:wallet.example"

    unsupported_claims =
      claims
      |> Map.put("iss", unsupported_subject)
      |> Map.put("sub", unsupported_subject)

    unsupported_token = sign(context.key, unsupported_claims, %{"kid" => unsupported_subject <> "#key-0"})

    assert {:error, :invalid_signature} =
             Siop.verify(wrong_key_token, audience: @audience, nonce: @nonce, now: @now)

    assert {:error, :invalid_subject} =
             Siop.verify(unsupported_token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "did:jwk enforces signature use, key operations, and algorithm metadata", context do
    for contradictory_jwk <- [
          Map.put(context.jwk, "use", "enc"),
          Map.put(context.jwk, "key_ops", ["sign"]),
          Map.put(context.jwk, "alg", "EdDSA")
        ] do
      subject = did_jwk(contradictory_jwk)

      claims =
        context.claims
        |> Map.delete("sub_jwk")
        |> Map.put("iss", subject)
        |> Map.put("sub", subject)

      token = sign(context.key, claims, %{"kid" => subject <> "#0"})

      assert {:error, :invalid_subject} =
               Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
    end
  end

  test "accepts an all-string audience array containing the RP Client ID", context do
    claims = Map.put(context.claims, "aud", ["another-audience", @audience])
    token = sign(context.key, claims)

    assert {:ok, _verified} = Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "verify/3 accepts audience and nonce as positional arguments", context do
    now = System.system_time(:second)

    claims =
      context.claims
      |> Map.put("iat", now)
      |> Map.put("exp", now + 300)

    token = sign(context.key, claims)

    assert {:ok, %{subject: context.subject, jwk: context.jwk}} ==
             Siop.verify(token, @audience, @nonce)
  end

  test "rejects a wrong nonce", context do
    token = sign(context.key, context.claims)

    assert {:error, :invalid_nonce} =
             Siop.verify(token, audience: @audience, nonce: "wrong-nonce", now: @now)
  end

  test "rejects a missing nonce claim", context do
    token = sign(context.key, Map.delete(context.claims, "nonce"))

    assert {:error, :invalid_nonce} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects a wrong audience", context do
    token = sign(context.key, context.claims)

    assert {:error, :invalid_audience} =
             Siop.verify(token, audience: "https://other-rp.example/client", nonce: @nonce, now: @now)
  end

  test "rejects a malformed audience array even when it contains the RP Client ID", context do
    token = sign(context.key, Map.put(context.claims, "aud", [@audience, 42]))

    assert {:error, :invalid_audience} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects sub when it is not the RFC 7638 thumbprint", context do
    claims = Map.put(context.claims, "sub", String.duplicate("A", 43))
    token = sign(context.key, claims)

    assert {:error, :invalid_subject} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects an issuer other than the static identifier or sub", context do
    token = sign(context.key, Map.put(context.claims, "iss", "https://wallet.example"))

    assert {:error, :invalid_issuer} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects an expired token at the exact exp boundary", context do
    token = sign(context.key, Map.put(context.claims, "exp", @now))

    assert {:error, :expired} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "requires well-typed exp and iat claims", context do
    for {claims, expected} <- [
          {Map.delete(context.claims, "exp"), :expired},
          {Map.put(context.claims, "exp", "later"), :expired},
          {Map.delete(context.claims, "iat"), :invalid_claims},
          {Map.put(context.claims, "iat", -1), :invalid_claims}
        ] do
      token = sign(context.key, claims)

      assert {:error, ^expected} =
               Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
    end
  end

  test "checks iat and optional nbf with the 60-second clock-skew boundary", context do
    for {claim, offset, expected} <- [
          {"iat", 60, :ok},
          {"iat", 61, :not_yet_valid},
          {"nbf", 60, :ok},
          {"nbf", 61, :not_yet_valid}
        ] do
      token = sign(context.key, Map.put(context.claims, claim, @now + offset))
      result = Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)

      case expected do
        :ok -> assert {:ok, _verified} = result
        error -> assert {:error, ^error} = result
      end
    end
  end

  test "rejects a present malformed nbf instead of treating it as absent", context do
    token = sign(context.key, Map.put(context.claims, "nbf", "tomorrow"))

    assert {:error, :invalid_claims} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects a tampered signature", context do
    token = context.key |> sign(context.claims) |> tamper_signature()

    assert {:error, :invalid_signature} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects a token not signed by its embedded holder key", context do
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    token = sign(context.key, Map.put(context.claims, "sub_jwk", public_map(other)))

    assert {:error, :invalid_signature} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects private material in sub_jwk", context do
    {_metadata, private_jwk} = JOSE.JWK.to_map(context.key)
    token = sign(context.key, Map.put(context.claims, "sub_jwk", private_jwk))

    assert {:error, :invalid_sub_jwk} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects conflicting protected-header and payload sub_jwk values", context do
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    token = sign(context.key, context.claims, %{"sub_jwk" => public_map(other)})

    assert {:error, :invalid_sub_jwk} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects a missing sub_jwk", context do
    token = sign(context.key, Map.delete(context.claims, "sub_jwk"))

    assert {:error, :missing_sub_jwk} =
             Siop.verify(token, audience: @audience, nonce: @nonce, now: @now)
  end

  test "rejects unsupported critical headers and an unexpected typ", context do
    critical = sign(context.key, context.claims, %{"crit" => ["wallet_extension"], "wallet_extension" => true})
    wrong_typ = sign(context.key, context.claims, %{"typ" => "at+jwt"})

    assert {:error, :unsupported_critical_header} =
             Siop.verify(critical, audience: @audience, nonce: @nonce, now: @now)

    assert {:error, :unexpected_typ} =
             Siop.verify(wrong_typ, audience: @audience, nonce: @nonce, now: @now)
  end

  test "fails closed when required RP inputs are absent", context do
    token = sign(context.key, context.claims)

    assert {:error, :invalid_audience} = Siop.verify(token, nonce: @nonce, now: @now)
    assert {:error, :invalid_nonce} = Siop.verify(token, audience: @audience, now: @now)
  end

  defp public_map(key) do
    {_metadata, jwk_map} = JOSE.JWK.to_public_map(key)
    jwk_map
  end

  defp did_jwk(jwk), do: "did:jwk:" <> encode_json(jwk)
  defp encode_json(value), do: value |> JSON.encode!() |> Base.url_encode64(padding: false)

  defp did_key(%{"crv" => "Ed25519", "x" => x}) do
    public_key = Base.url_decode64!(x, padding: false)
    "did:key:z" <> encode_base58(<<0xED, 0x01>> <> public_key)
  end

  defp did_key(%{"crv" => "P-256", "x" => x, "y" => y}) do
    x_bytes = Base.url_decode64!(x, padding: false)
    y_bytes = Base.url_decode64!(y, padding: false)
    prefix = if band(:binary.last(y_bytes), 1) == 0, do: 2, else: 3
    "did:key:z" <> encode_base58(<<0x80, 0x24, prefix>> <> x_bytes)
  end

  defp encode_base58(bytes) do
    zeroes = count_leading_zeroes(bytes, 0)
    encoded = bytes |> :binary.decode_unsigned() |> encode_base58_integer("")
    String.duplicate("1", zeroes) <> encoded
  end

  defp count_leading_zeroes(<<0, rest::binary>>, count), do: count_leading_zeroes(rest, count + 1)
  defp count_leading_zeroes(_rest, count), do: count

  defp encode_base58_integer(0, encoded), do: encoded

  defp encode_base58_integer(number, encoded) do
    character = binary_part(@base58_alphabet, rem(number, 58), 1)
    encode_base58_integer(div(number, 58), character <> encoded)
  end

  defp sign(key, claims, header_overrides \\ %{}) do
    header = Map.merge(%{"alg" => "ES256", "typ" => "JWT"}, header_overrides)
    {_signed, compact} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end

  defp tamper_signature(token) do
    [header, payload, signature] = String.split(token, ".", parts: 3)
    <<first, rest::binary>> = signature
    replacement = if first == ?A, do: ?B, else: ?A
    Enum.join([header, payload, <<replacement, rest::binary>>], ".")
  end
end
