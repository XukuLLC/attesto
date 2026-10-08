defmodule Attesto.PresentationPolicyBoundaryTest do
  use ExUnit.Case, async: false

  alias Attesto.{JWE, JWS, PresentationSession, SdJwtVc, VpToken}
  alias Attesto.PresentationSessionStore.ETS, as: Store

  @audience "registered-verifier"

  setup do
    start_supervised!(Store)
    now = System.system_time(:second)
    issuer = JOSE.JWK.generate_key({:ec, "P-256"})
    holder = JOSE.JWK.generate_key({:ec, "P-256"})
    public = holder |> JOSE.JWK.to_public_map() |> elem(1)

    credential =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem(issuer)],
        cnf: %{"jwk" => public},
        claims: %{"given_name" => "Synthetic"},
        iat: now
      )

    %{
      issuer: issuer,
      holder: holder,
      credential: credential,
      now: now,
      public: issuer |> JOSE.JWK.to_public_map() |> elem(1)
    }
  end

  test "request-bound verification rejects extra IDs before issuer resolution", ctx do
    options = options(ctx, "nonce")
    parent = self()

    resolver = fn _issuer ->
      send(parent, :issuer_lookup)
      ctx.public
    end

    options = Keyword.delete(options, :issuer_jwks) ++ [resolve_issuer: resolver]

    assert {:error, {:unexpected_query_ids, ["unsolicited"]}} =
             VpToken.verify(%{"requested" => ["not-a-presentation"], "unsolicited" => ["also-invalid"]}, options)

    refute_received :issuer_lookup
  end

  test "optional IDs retain constraints without becoming required", ctx do
    constraints = %{
      "requested" => %{format: "dc+sd-jwt", vct_values: ["identity"]},
      "optional" => %{format: "dc+sd-jwt", vct_values: ["other-type"]}
    }

    opts = options(ctx, "nonce") ++ [permitted_query_ids: ["requested", "optional"], query_constraints: constraints]
    presentation = presentation(ctx, "nonce")
    assert {:ok, %{"requested" => [_]}} = VpToken.verify(%{"requested" => [presentation]}, opts)

    assert {:error, {"optional", :vct_mismatch}} =
             VpToken.verify(%{"requested" => [presentation], "optional" => [presentation]}, opts)

    assert {:error, {:missing_credentials, ["requested"]}} = VpToken.verify(%{}, opts)
  end

  test "unrestricted low-level verification remains available only without a requested ID set", ctx do
    opts = Keyword.delete(options(ctx, "nonce"), :expected_query_ids)
    presentation = presentation(ctx, "nonce")
    assert {:ok, %{"arbitrary" => [_]}} = VpToken.verify(%{"arbitrary" => [presentation]}, opts)

    assert {:error, {:unexpected_query_ids, ["arbitrary"]}} =
             VpToken.verify(%{"arbitrary" => [presentation]}, opts ++ [permitted_query_ids: []])
  end

  test "sessions reject malformed and unsolicited plaintext or decrypted responses without completion", ctx do
    for encrypted? <- [false, true], invalid <- [:scalar, :empty, :wrong_type, :extra_id] do
      attrs = %{
        audience: @audience,
        expected_query_ids: ["requested"],
        issuer_trust: {:issuer_jwks, ctx.public},
        permitted_query_ids: ["requested", "optional"],
        query_constraints: %{"requested" => %{format: "dc+sd-jwt", vct_values: ["identity"]}}
      }

      {:ok, session} = PresentationSession.create(Store, attrs, now: ctx.now)

      if encrypted?,
        do: assert(:ok == PresentationSession.attach_response_encryption_jwk(Store, session.id, ctx.public))

      valid = presentation(ctx, session.nonce)

      response =
        case invalid do
          :scalar -> %{"requested" => valid}
          :empty -> %{"requested" => []}
          :wrong_type -> %{"requested" => [123]}
          :extra_id -> %{"requested" => [valid], "unsolicited" => [valid]}
        end

      response = transport_response(response, encrypted?, ctx.issuer)

      assert {:error, {:invalid_presentation, _}} =
               PresentationSession.verify_response(Store, {:state, session.id}, response,
                 now: ctx.now,
                 permitted_query_ids: ["requested", "optional", "unsolicited"]
               )

      assert {:ok, %{data: %{status: :pending}}} = Store.get(session.id)

      assert {:ok, %{"requested" => [_]}} =
               PresentationSession.verify_response(Store, {:state, session.id}, %{"requested" => [valid]}, now: ctx.now)
    end
  end

  test "sessions retain optional-query constraints and reject malformed trusted ID sets", ctx do
    attrs = %{
      audience: @audience,
      expected_query_ids: ["requested"],
      permitted_query_ids: ["requested", "optional"],
      issuer_trust: {:issuer_jwks, ctx.public},
      query_constraints: %{"optional" => %{vct_values: ["other-type"]}}
    }

    for invalid <- [nil, "requested", ["requested"], ["requested", "requested"], ["requested", nil]] do
      assert {:error, :invalid_attrs} = PresentationSession.create(Store, %{attrs | permitted_query_ids: invalid})
    end

    {:ok, session} = PresentationSession.create(Store, attrs, now: ctx.now)
    value = presentation(ctx, session.nonce)

    assert {:error, {:invalid_presentation, {"optional", :vct_mismatch}}} =
             PresentationSession.verify_response(
               Store,
               {:state, session.id},
               %{"requested" => [value], "optional" => [value]},
               now: ctx.now
             )

    assert {:ok, %{"requested" => [_]}} =
             PresentationSession.verify_response(Store, {:state, session.id}, %{"requested" => [value]}, now: ctx.now)
  end

  defp transport_response(response, false, _key), do: response

  defp transport_response(response, true, key) do
    {:ok, compact} =
      key
      |> JOSE.JWK.to_public_map()
      |> elem(1)
      |> JWE.encrypt(Jason.encode!(%{"vp_token" => response}), %{"alg" => "ECDH-ES", "enc" => "A128GCM"})

    {:ok, plaintext, _header} = JWE.decrypt(key, compact)
    Jason.decode!(plaintext)["vp_token"]
  end

  defp options(ctx, nonce),
    do: [nonce: nonce, audience: @audience, issuer_jwks: ctx.public, expected_query_ids: ["requested"], now: ctx.now]

  defp presentation(ctx, nonce) do
    proof =
      JWS.sign_compact(pem(ctx.holder), %{"alg" => "ES256", "typ" => "kb+jwt"}, %{
        "nonce" => nonce,
        "aud" => @audience,
        "iat" => ctx.now,
        "sd_hash" => :crypto.hash(:sha256, ctx.credential) |> JWS.encode64()
      })

    ctx.credential <> proof
  end

  defp pem(key), do: key |> JOSE.JWK.to_pem() |> elem(1)
end
