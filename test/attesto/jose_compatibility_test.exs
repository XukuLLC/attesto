defmodule Attesto.JOSECompatibilityTest do
  @moduledoc false
  use ExUnit.Case, async: false

  setup do
    original_json_module = JOSE.json_module()
    :ok = JOSE.json_module(:jose_json_otp)
    on_exit(fn -> JOSE.json_module(original_json_module) end)
  end

  test "EC keys export and import through a public JWK before ES256 verification" do
    private_key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public_map} = JOSE.JWK.to_public_map(private_key)
    public_key = JOSE.JWK.from_map(public_map)
    payload = ~s({"sub":"minimum-version-consumer"})

    {_, compact} =
      private_key
      |> JOSE.JWS.sign(payload, %{"alg" => "ES256", "typ" => "JWT"})
      |> JOSE.JWS.compact()

    assert %{"crv" => "P-256", "kty" => "EC", "x" => _x, "y" => _y} = public_map
    refute Map.has_key?(public_map, "d")
    assert {true, ^payload, _verified_jws} = JOSE.JWS.verify_strict(public_key, ["ES256"], compact)
  end

  test "the builtin OTP JSON backend encodes an Elixir nil JWT claim as null" do
    private_key = JOSE.JWK.generate_key({:ec, "P-256"})

    {_, compact} =
      private_key
      |> JOSE.JWT.sign(%{"alg" => "ES256"}, %{"optional" => nil, "sub" => "json-consumer"})
      |> JOSE.JWS.compact()

    [_header, encoded_payload, _signature] = String.split(compact, ".")
    payload = encoded_payload |> Base.url_decode64!(padding: false) |> JSON.decode!()

    assert payload == %{"optional" => nil, "sub" => "json-consumer"}
  end
end
