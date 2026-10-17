defmodule Attesto.AuthorizationCodeReuseETSTest do
  @moduledoc false
  # The ETS reference CodeStore retains a marker after a completed redemption,
  # so a re-presentation carries the context needed for containment.
  #
  # async: false - `Attesto.CodeStore.ETS` is a named singleton; running this
  # concurrently with any other test that boots the same named store races on
  # shared state.
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore.ETS
  alias Attesto.PKCE

  @verifier "the-quick-brown-fox-jumps-over_the.lazy~dog-0123"
  @redirect_uri "https://app.example.com/cb"
  @client_id "oc_app"
  @subject "usr_42"
  @scope ["documents.read"]
  @family_id "fam_abc123"

  setup do
    start_supervised!(ETS)
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  defp code_attrs(challenge, overrides) do
    Map.merge(
      %{
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_challenge: challenge,
        scope: @scope,
        subject: @subject
      },
      overrides
    )
  end

  defp redeem_params(overrides \\ %{}) do
    Map.merge(%{redirect_uri: @redirect_uri, code_verifier: @verifier, client_id: @client_id}, overrides)
  end

  describe "redeem/4 with ETS reuse tracking" do
    test "a finalized redemption is reported as reuse on the second attempt", %{challenge: challenge} do
      {:ok, code} = AuthorizationCode.issue(ETS, code_attrs(challenge, %{family_id: @family_id}))

      assert {:ok, %Grant{family_id: @family_id} = grant} =
               AuthorizationCode.redeem(ETS, code, redeem_params())

      assert :ok = AuthorizationCode.finalize(ETS, code, grant)

      assert {:error, {:reuse, %{family_id: nil, subject: @subject}}} =
               AuthorizationCode.redeem(ETS, code, redeem_params())
    end
  end
end
