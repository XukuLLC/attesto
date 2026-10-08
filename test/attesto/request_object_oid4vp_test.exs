defmodule Attesto.RequestObjectOid4vpTest do
  use ExUnit.Case, async: true

  alias Attesto.RequestObject

  @now 1_700_000_000
  @client "https://verifier.example"
  @audience "https://self-issued.me/v2"

  setup_all do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, public} = JOSE.JWK.to_public_map(key)
    %{key: key, public: public}
  end

  defp claims, do: %{"client_id" => @client, "aud" => @audience, "iat" => @now, "exp" => @now + 60}

  defp sign(key, claims, header \\ %{"alg" => "ES256", "typ" => "oauth-authz-req+jwt"}) do
    {_jws, jwt} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    jwt
  end

  defp options, do: [profile: :oid4vp, audience: @audience, now: @now]

  test "OID4VP ignores iss but default JAR still requires issuer binding", context do
    for request <- [claims(), Map.put(claims(), "iss", "https://other.example"), Map.put(claims(), "iss", %{})] do
      jwt = sign(context.key, request)
      assert {:ok, _, ^request} = RequestObject.verify_with_claims(jwt, context.public, options())

      assert {:error, :invalid_issuer} =
               RequestObject.verify(jwt, context.public, issuer: @client, audience: @audience, now: @now)
    end

    jwt = sign(context.key, Map.put(claims(), "iss", @client))
    assert {:ok, _} = RequestObject.verify(jwt, context.public, issuer: @client, audience: @audience, now: @now)
  end

  test "OID4VP mandatory type cannot be overridden", context do
    for header <- [
          %{"alg" => "ES256"},
          %{"alg" => "ES256", "typ" => "JWT"},
          %{"alg" => "ES256", "typ" => "application/oauth-authz-req+jwt"}
        ],
        policy <- [nil, [nil, "JWT"]] do
      assert {:error, :invalid_typ} =
               RequestObject.verify(
                 sign(context.key, claims(), header),
                 context.public,
                 Keyword.put(options(), :accepted_typ, policy)
               )
    end
  end

  test "OID4VP still enforces client identity, audience and time", context do
    for {request, expected} <- [
          {Map.delete(claims(), "client_id"), :invalid_issuer},
          {Map.put(claims(), "client_id", ""), :invalid_issuer},
          {Map.delete(claims(), "aud"), :invalid_audience},
          {Map.put(claims(), "aud", "other"), :invalid_audience},
          {Map.put(claims(), "exp", @now), :expired},
          {Map.put(claims(), "iat", @now + 1000), :not_yet_valid}
        ] do
      assert {:error, ^expected} = RequestObject.verify(sign(context.key, request), context.public, options())
    end
  end
end
