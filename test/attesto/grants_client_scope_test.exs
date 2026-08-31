defmodule Attesto.GrantsClientScopeTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore
  alias Attesto.PKCE
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken

  @verifier "client-scope-verifier_unreserved.chars-aaaaaaaaaa~0"

  setup do
    start_supervised!(CodeStore.ETS)
    start_supervised!(RefreshStore.ETS)
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  defp issue_code(challenge, client_id) do
    {:ok, code} =
      AuthorizationCode.issue(CodeStore.ETS, %{
        client_id: client_id,
        redirect_uri: "https://app.example.com/cb",
        code_challenge: challenge,
        subject: "usr_42",
        scope: ["documents.read"]
      })

    code
  end

  defp redeem(code, extra) do
    params = Map.merge(%{redirect_uri: "https://app.example.com/cb", code_verifier: @verifier}, extra)
    AuthorizationCode.redeem(CodeStore.ETS, code, params)
  end

  describe "authorization code cross-client binding" do
    test "a code redeemed by the issuing client succeeds", %{challenge: challenge} do
      code = issue_code(challenge, "oc_app_a")
      assert {:ok, %Grant{client_id: "oc_app_a"}} = redeem(code, %{client_id: "oc_app_a"})
    end

    test "a code redeemed by a different client is rejected", %{challenge: challenge} do
      code = issue_code(challenge, "oc_app_a")
      assert {:error, :client_mismatch} = redeem(code, %{client_id: "oc_app_b"})
    end

    test "redeeming without a presenting client is fail-closed (:client_required)", %{challenge: challenge} do
      code = issue_code(challenge, "oc_app_a")
      assert {:error, :client_required} = redeem(code, %{})
    end

    test "a host relying on PKCE alone opts out with allow_missing_client_id?", %{challenge: challenge} do
      code = issue_code(challenge, "oc_app_a")
      params = %{redirect_uri: "https://app.example.com/cb", code_verifier: @verifier}

      assert {:ok, %Grant{}} =
               AuthorizationCode.redeem(CodeStore.ETS, code, params, allow_missing_client_id?: true)
    end

    test "a non-boolean opt-out cannot bypass client binding", %{challenge: challenge} do
      for invalid <- ["false", 1, {:error, :unavailable}] do
        code = issue_code(challenge, "oc_app_a")
        params = %{redirect_uri: "https://app.example.com/cb", code_verifier: @verifier}

        assert_raise ArgumentError, ~r/:allow_missing_client_id\? must be true or false/, fn ->
          AuthorizationCode.redeem(CodeStore.ETS, code, params, allow_missing_client_id?: invalid)
        end

        assert {:ok, %Grant{}} =
                 AuthorizationCode.redeem(CodeStore.ETS, code, Map.put(params, :client_id, "oc_app_a"))
      end
    end
  end

  describe "refresh cross-client binding" do
    test "rotation by the issuing client succeeds" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", client_id: "oc_app_a", scope: ["documents.read"]})

      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_app_a")
    end

    test "rotation by a different client is rejected and does not burn the token" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", client_id: "oc_app_a"})

      assert {:error, :client_mismatch} = RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_app_b")
      # Recoverable: the legitimate client can still rotate.
      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_app_a")
    end

    test "a non-boolean opt-out cannot bypass refresh-token client binding" do
      for invalid <- ["false", 1, {:error, :unavailable}] do
        {:ok, %{token: token}} =
          RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_42", client_id: "oc_app_a"})

        assert_raise ArgumentError, ~r/:allow_missing_client_id\? must be true or false/, fn ->
          RefreshToken.rotate(RefreshStore.ETS, token, allow_missing_client_id?: invalid)
        end

        assert {:ok, %{generation: 1}} =
                 RefreshToken.rotate(RefreshStore.ETS, token, client_id: "oc_app_a")
      end
    end
  end

  describe "refresh scope narrowing (RFC 6749 §6)" do
    setup do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{
          subject: "usr_42",
          scope: ["documents.read", "documents.write", "positions.read"]
        })

      %{t0: t0}
    end

    test "a subset request narrows the successor's scope", %{t0: t0} do
      assert {:ok, %{token: t1, context: ctx}} =
               RefreshToken.rotate(RefreshStore.ETS, t0, scope: ["documents.read"])

      assert ctx.scope == ["documents.read"]

      # The narrowed scope sticks: the next rotation cannot re-widen back to
      # the original grant.
      assert {:error, :invalid_scope} =
               RefreshToken.rotate(RefreshStore.ETS, t1, scope: ["documents.write"])
    end

    test "no scope request keeps the full granted scope", %{t0: t0} do
      assert {:ok, %{context: ctx}} = RefreshToken.rotate(RefreshStore.ETS, t0)
      assert ctx.scope == ["documents.read", "documents.write", "positions.read"]
    end

    test "a widening request is refused and does not burn the token", %{t0: t0} do
      assert {:error, :invalid_scope} =
               RefreshToken.rotate(RefreshStore.ETS, t0, scope: ["documents.read", "billing.read"])

      # Token intact: a valid narrowing retry still works.
      assert {:ok, %{generation: 1}} = RefreshToken.rotate(RefreshStore.ETS, t0, scope: ["documents.read"])
    end
  end
end
