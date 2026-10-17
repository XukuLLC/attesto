defmodule Attesto.Test.DPoPFixtures do
  @moduledoc false

  alias Attesto.Test.JWT

  def now, do: System.system_time(:second)

  def ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})
  def rsa_key(bits \\ 2048), do: JOSE.JWK.generate_key({:rsa, bits})
  def ed25519_key, do: JOSE.JWK.generate_key({:okp, :Ed25519})

  def public_map(%JOSE.JWK{} = key) do
    {_, map} = JOSE.JWK.to_public_map(key)
    map
  end

  def claims(http_method, http_uri, now, overrides \\ %{}) do
    Map.merge(
      %{
        "htm" => http_method,
        "htu" => http_uri,
        "iat" => now,
        "jti" => "jti-" <> Integer.to_string(System.unique_integer([:positive]))
      },
      overrides
    )
  end

  def header(jwk_map, overrides \\ %{}) do
    Map.merge(%{"alg" => "ES256", "jwk" => jwk_map, "typ" => "dpop+jwt"}, overrides)
  end

  def sign(key, header, claims), do: JWT.sign_compact(key, header, claims)

  def verification_options(http_method, http_uri, extra \\ []) do
    Keyword.merge([http_method: http_method, http_uri: http_uri], extra)
  end

  def encode_segment(map) do
    map
    |> JSON.encode!()
    |> Base.url_encode64(padding: false)
  end

  def reheader(signed_compact, new_header_map) do
    [_old_header, payload, signature] = String.split(signed_compact, ".")
    Enum.join([encode_segment(new_header_map), payload, signature], ".")
  end
end
