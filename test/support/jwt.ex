defmodule Attesto.Test.JWT do
  @moduledoc false

  def sign_compact(jwk, header, claims) do
    if Map.get(header, "alg") in ["PS256", "PS384", "PS512"] do
      Attesto.JWS.sign_compact_jwk(jwk, Map.put_new(header, "typ", "JWT"), claims)
    else
      {_header, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
      compact
    end
  end
end
