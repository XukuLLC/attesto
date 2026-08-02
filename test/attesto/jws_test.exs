defmodule Attesto.JWSTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.JWS

  defp public_map(key, overrides) do
    {_kty, map} = JOSE.JWK.to_public_map(key)
    Map.merge(map, overrides)
  end

  defp signed_jwt(key, kid) do
    {_, jwt} =
      key
      |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => kid}, %{"ok" => true})
      |> JOSE.JWS.compact()

    jwt
  end

  test "keeps candidate order and narrows by kid after algorithm filtering" do
    first = JOSE.JWK.generate_key({:ec, "P-256"})
    second = JOSE.JWK.generate_key({:ec, "P-256"})
    second_kid = JOSE.JWK.thumbprint(second)

    candidates =
      JWS.verification_candidates(
        [
          public_map(first, %{"kid" => JOSE.JWK.thumbprint(first), "alg" => "ES256"}),
          public_map(second, %{"kid" => second_kid, "alg" => "ES256"})
        ],
        accepted_algs: ["ES256"],
        kid: second_kid
      )

    assert [{^second_kid, "ES256", %JOSE.JWK{}}] = candidates
  end

  test "reject_set and skip preserve their distinct malformed-key policies" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    valid = public_map(key, %{"kid" => "valid", "alg" => "ES256"})
    malformed = %{"not" => "a jwk"}

    assert JWS.verification_candidates([valid, malformed], accepted_algs: ["ES256"], malformed_key: :reject_set) ==
             []

    assert [{"valid", "ES256", %JOSE.JWK{}}] =
             JWS.verification_candidates([malformed, valid],
               accepted_algs: ["ES256"],
               malformed_key: :skip
             )
  end

  test "strict verification tries candidates in order and exposes the selected key when requested" do
    signer = JOSE.JWK.generate_key({:ec, "P-256"})
    wrong = JOSE.JWK.generate_key({:ec, "P-256"})
    signer_kid = JOSE.JWK.thumbprint(signer)
    jwt = signed_jwt(signer, signer_kid)

    candidates =
      JWS.verification_candidates(
        [
          public_map(wrong, %{"kid" => "wrong", "alg" => "ES256"}),
          public_map(signer, %{"kid" => signer_kid, "alg" => "ES256"})
        ],
        accepted_algs: ["ES256"]
      )

    assert {:ok, %{"ok" => true}, {^signer_kid, "ES256", %JOSE.JWK{}}} =
             JWS.verify_strict(jwt, candidates, return_key?: true)

    wrong_candidates =
      JWS.verification_candidates(public_map(wrong, %{"kid" => "wrong", "alg" => "ES256"}),
        accepted_algs: ["ES256"]
      )

    assert {:error, :wrong_key} = JWS.verify_strict(jwt, wrong_candidates, terminal_error: :wrong_key)
  end
end
