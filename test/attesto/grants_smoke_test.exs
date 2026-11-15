defmodule Attesto.GrantsSmokeTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore
  alias Attesto.PKCE
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Secret

  @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"

  setup do
    start_supervised!(CodeStore.ETS)
    start_supervised!(RefreshStore.ETS)
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  defp code_attrs(challenge, overrides \\ %{}) do
    Map.merge(
      %{
        client_id: "oc_app",
        redirect_uri: "https://app.example.com/cb",
        code_challenge: challenge,
        scope: ["documents.read"],
        subject: "usr_42"
      },
      overrides
    )
  end

  defp redeem_params(overrides \\ %{}) do
    Map.merge(
      %{redirect_uri: "https://app.example.com/cb", code_verifier: @verifier, client_id: "oc_app"},
      overrides
    )
  end

  describe "Secret" do
    test "generate is unique and hash is deterministic" do
      a = Secret.generate()
      b = Secret.generate()
      refute a == b
      assert Secret.hash(a) == Secret.hash(a)
      assert Secret.hash(a) != Secret.hash(b)
    end
  end

  describe "authorization code" do
    test "issue then redeem returns the grant context", %{challenge: challenge} do
      assert {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      assert {:ok, %Grant{} = grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())

      assert grant.client_id == "oc_app"
      assert grant.subject == "usr_42"
      assert grant.scope == ["documents.read"]
      assert grant.redirect_uri == "https://app.example.com/cb"
    end

    test "a code is single-use: the second redeem fails", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))
      assert {:ok, _} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
      assert {:error, :invalid_grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "a wrong redirect_uri is rejected without consuming the code", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:error, :redirect_uri_mismatch} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{redirect_uri: "https://evil/cb"}))

      # The correct presentation can still redeem the code.
      assert {:ok, _grant} = AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())
    end

    test "a wrong PKCE verifier is rejected", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge))

      assert {:error, :pkce_failed} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(%{code_verifier: String.duplicate("z", 50)}))
    end

    test "an expired code is rejected", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge), ttl: 1, now: 1_000)

      assert {:error, :expired} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params(), now: 2_000)
    end

    test "a DPoP-bound code requires the matching jkt", %{challenge: challenge} do
      jkt = Secret.hash("some-dpop-key")
      {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{dpop_jkt: jkt}))

      assert {:error, :dpop_proof_required} =
               AuthorizationCode.redeem(CodeStore.ETS, code, redeem_params())

      {:ok, code2} = AuthorizationCode.issue(CodeStore.ETS, code_attrs(challenge, %{dpop_jkt: jkt}))

      assert {:ok, %Grant{dpop_jkt: ^jkt}} =
               AuthorizationCode.redeem(CodeStore.ETS, code2, redeem_params(%{dpop_jkt: jkt}))
    end

    test "PKCE is mandatory: a bad challenge is refused at issue", %{challenge: _} do
      assert {:error, :invalid_code_challenge} =
               AuthorizationCode.issue(CodeStore.ETS, code_attrs("not-a-valid-challenge"))
    end
  end

  describe "refresh token rotation and reuse detection" do
    test "rotate consumes the old token and mints a successor" do
      {:ok, %{token: t0, family_id: fam, generation: 0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", scope: ["documents.read"]})

      assert {:ok, %{token: t1, family_id: ^fam, generation: 1, context: ctx}} =
               RefreshToken.rotate(RefreshStore.ETS, t0)

      assert ctx.subject == "usr_42"
      refute t1 == t0
    end

    test "an immediate honest retry of an already-rotated token is idempotent" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42"})
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0)

      # A lost response can make the legitimate client retry the just-consumed
      # parent. Within the short grace window, return the same successor.
      assert {:ok, %{token: ^t1}} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "strict rotation mode treats an already-rotated token as reuse" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42"})
      {:ok, %{token: t1}} = RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, rotation_grace_seconds: 0)

      # The whole family is revoked, so the live t1 no longer rotates.
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, t1)
    end

    test "an unknown token is invalid_grant" do
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, "nope")
    end

    test "a DPoP-bound refresh requires the matching jkt to rotate" do
      jkt = Secret.hash("dpop-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", dpop_jkt: jkt})

      assert {:error, :dpop_proof_required} = RefreshToken.rotate(RefreshStore.ETS, t0)
    end

    test "a DPoP-bound refresh rotates with the matching jkt" do
      jkt = Secret.hash("dpop-key")
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", dpop_jkt: jkt})
      assert {:ok, %{token: _t1}} = RefreshToken.rotate(RefreshStore.ETS, t0, dpop_jkt: jkt)
    end
  end
end
