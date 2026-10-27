defmodule Attesto.JWSECDSALengthTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.JWS

  @algorithms [{"ES256", "P-256", 32}, {"ES384", "P-384", 48}, {"ES512", "P-521", 66}]

  for {alg, curve, half} <- @algorithms do
    test "#{alg} accepts only the fixed-length R || S encoding" do
      alg = unquote(alg)
      half = unquote(half)
      private = JOSE.JWK.generate_key({:ec, unquote(curve)})
      public = private |> JOSE.JWK.to_public_map() |> elem(1)
      candidates = JWS.verification_candidates(public, alg: alg)
      claims = %{"sub" => "synthetic-subject"}

      {_jws, token} = private |> JOSE.JWT.sign(%{"alg" => alg}, claims) |> JOSE.JWS.compact()
      assert {:ok, ^claims} = JWS.verify_strict(token, candidates)

      [header, payload, encoded] = String.split(token, ".")
      {:ok, <<r::binary-size(half), s::binary-size(half)>>} = JWS.decode64(encoded)

      # Leading zero bytes leave both integers unchanged, so only the length
      # distinguishes these encodings from the canonical signature.
      for padding <- 1..3 do
        zeros = :binary.copy(<<0>>, padding)
        padded = Enum.join([header, payload, JWS.encode64(zeros <> r <> zeros <> s)], ".")
        assert {:error, :invalid_signature} = JWS.verify_strict(padded, candidates)
      end
    end
  end
end
