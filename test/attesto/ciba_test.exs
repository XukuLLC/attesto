defmodule Attesto.CIBATest do
  use ExUnit.Case, async: false

  alias Attesto.CIBA
  alias Attesto.CIBA.Grant
  alias Attesto.CIBA.Request
  alias Attesto.CIBAStore.ETS, as: Store

  @now 1_700_000_000
  @client_id "ciba-client-1"
  @notification_token "8d67dc78-7faa-4d41-aabd-67707b374255"

  setup do
    start_supervised!(Store)
    Store.reset()
    :ok
  end

  defp request(overrides \\ %{}) do
    struct!(
      Request,
      Map.merge(
        %{
          client_id: @client_id,
          delivery_mode: :poll,
          hint: {:login_hint, "user@example.com"},
          scope: ["openid", "accounts.read"]
        },
        overrides
      )
    )
  end

  defp issue(request_overrides \\ %{}, attrs \\ %{}, opts \\ []) do
    attrs = Map.merge(%{subject: "usr_1"}, attrs)
    {:ok, issued} = CIBA.issue(Store, request(request_overrides), attrs, Keyword.put_new(opts, :now, @now))
    issued
  end

  describe "issue/4 (§7.3 acknowledgement)" do
    test "returns an auth_req_id in the §7.3 charset with >=160 bits of entropy, plus expires_in and interval" do
      %{auth_req_id: id, expires_in: expires_in, interval: interval} = issue()

      assert id =~ ~r/\A[A-Za-z0-9._-]+\z/
      # 32 CSPRNG bytes → 43 base64url chars; well above the 160-bit floor (27 chars).
      assert byte_size(id) == 43
      assert expires_in == 120
      assert interval == 5
    end

    test "issued ids are unique across draws (CSPRNG)" do
      ids = for _ <- 1..50, do: issue().auth_req_id
      assert length(Enum.uniq(ids)) == 50
    end

    test "requires a subject (the hint must already be resolved)" do
      assert {:error, :invalid_subject} = CIBA.issue(Store, request(), %{})
      assert {:error, :invalid_subject} = CIBA.issue(Store, request(), %{subject: ""})
    end

    test "honours requested_expiry under the cap" do
      assert %{expires_in: 30} = issue(%{requested_expiry: 30})
      assert %{expires_in: 600} = issue(%{requested_expiry: 86_400})
      assert %{expires_in: 200} = issue(%{requested_expiry: 86_400}, %{}, max_expires_in: 200)
    end

    test "a push-mode request has no interval (nothing to poll)" do
      assert %{interval: nil} =
               issue(%{delivery_mode: :push, client_notification_token: @notification_token})
    end
  end

  describe "redeem/4 — CIBA Core §10.1/§11 state machine" do
    test "pending yields authorization_pending; approval then yields the grant; reuse is invalid_grant" do
      %{auth_req_id: id} = issue()

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)

      assert {:ok, _decision} =
               CIBA.approve(Store, id, %{subject: "usr_1", scope: ["openid"], acr: "urn:mace:phr"}, now: @now + 5)

      assert {:ok, %Grant{} = grant} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 10)
      assert grant.client_id == @client_id
      assert grant.subject == "usr_1"
      assert grant.scope == ["openid"]
      assert grant.acr == "urn:mace:phr"
      assert grant.auth_time == @now + 5

      # Single-use: a second redemption of the consumed request is invalid_grant.
      assert {:error, :invalid_grant} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 20)
    end

    test "denial yields access_denied" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.deny(Store, id, now: @now + 5)
      assert {:error, :access_denied} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 10)
    end

    test "an expired auth_req_id yields expired_token, even after approval (expiry wins)" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 5)
      assert {:error, :expired_token} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 121)
    end

    test "polling faster than the issued interval yields slow_down (§11)" do
      %{auth_req_id: id, interval: 5} = issue()

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)
      # Immediate re-poll within the interval.
      assert {:error, :slow_down} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 2)
      # After the interval, polling resumes.
      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 7)
    end

    test "a ping-mode record enforces the interval too (§10.2: a polling ping client is a poll client)" do
      %{auth_req_id: id} =
        issue(%{client_notification_token: @notification_token, delivery_mode: :ping})

      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 1)
      assert {:error, :slow_down} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 2)
    end

    test "the first token request after issuance is never slow_down" do
      %{auth_req_id: id} = issue()
      assert {:error, :authorization_pending} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now)
    end

    test "an unknown auth_req_id is invalid_grant" do
      unknown = String.duplicate("a", 43)
      assert {:error, :invalid_grant} = CIBA.redeem(Store, unknown, %{client_id: @client_id}, now: @now)
    end

    test "a malformed auth_req_id fails closed before any store lookup" do
      # Outside the §7.3 charset / length floor: never hashed, never looked up.
      for bad <- ["", "short", "has space in it padpadpad", "bang!bang!bang!bang!"] do
        assert {:error, :invalid_grant} = CIBA.redeem(Store, bad, %{client_id: @client_id}, now: @now),
               "expected reject for #{inspect(bad)}"
      end
    end

    test "a client_id mismatch is invalid_grant and does not burn the request (§11: issued to another Client)" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      assert {:error, :invalid_grant} = CIBA.redeem(Store, id, %{client_id: "wrong"}, now: @now + 10)
      # The correct client still redeems (the mismatch did not consume it).
      assert {:ok, %Grant{}} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 16)
    end
  end

  describe "DPoP holder-of-key pre-binding (RFC 9449 §10)" do
    test "a request bound to a dpop_jkt redeems only with the matching proof key" do
      %{auth_req_id: id} = issue(%{}, %{dpop_jkt: "jkt-abc"})
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      assert {:error, :invalid_grant} =
               CIBA.redeem(Store, id, %{client_id: @client_id, dpop_jkt: "jkt-wrong"}, now: @now + 10)

      assert {:ok, %Grant{dpop_jkt: "jkt-abc"}} =
               CIBA.redeem(Store, id, %{client_id: @client_id, dpop_jkt: "jkt-abc"}, now: @now + 16)
    end
  end

  describe "approve/4 and deny/3 guards" do
    test "a decision is taken exactly once" do
      %{auth_req_id: id} = issue()
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)
      assert {:error, :already_decided} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 2)
      assert {:error, :already_decided} = CIBA.deny(Store, id, now: @now + 2)
    end

    test "a decision on an expired request is refused" do
      %{auth_req_id: id} = issue()
      assert {:error, :expired} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 121)
      assert {:error, :expired} = CIBA.deny(Store, id, now: @now + 121)
    end

    test "approval requires a subject, and it must be the user the request was issued for" do
      %{auth_req_id: id} = issue()

      assert {:error, :invalid_subject} = CIBA.approve(Store, id, %{}, now: @now + 1)
      # Fail-closed: approving as a different user than the hint resolved to.
      assert {:error, :subject_mismatch} = CIBA.approve(Store, id, %{subject: "usr_2"}, now: @now + 1)
      # The mismatch left the request pending for the right user.
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 2)
    end

    test "an unknown id is not_found; a malformed one is invalid_auth_req_id" do
      unknown = String.duplicate("a", 43)
      assert {:error, :not_found} = CIBA.approve(Store, unknown, %{subject: "usr_1"}, now: @now)
      assert {:error, :not_found} = CIBA.deny(Store, unknown, now: @now)
      assert {:error, :invalid_auth_req_id} = CIBA.approve(Store, "nope!", %{subject: "usr_1"}, now: @now)
      assert {:error, :invalid_auth_req_id} = CIBA.deny(Store, "nope!", now: @now)
    end

    test "both decisions return the ping-notification data (§10.2 fires on approval and denial)" do
      %{auth_req_id: approved} =
        issue(%{client_notification_token: @notification_token, delivery_mode: :ping})

      assert {:ok, decision} = CIBA.approve(Store, approved, %{subject: "usr_1"}, now: @now + 1)
      assert decision.delivery_mode == :ping
      assert decision.client_id == @client_id
      assert decision.client_notification_token == @notification_token

      %{auth_req_id: denied} =
        issue(%{client_notification_token: @notification_token, delivery_mode: :ping})

      assert {:ok, decision} = CIBA.deny(Store, denied, now: @now + 1)
      assert decision.client_notification_token == @notification_token
    end

    test "a poll-mode decision carries no notification token" do
      %{auth_req_id: id} = issue()

      assert {:ok, %{client_notification_token: nil, delivery_mode: :poll}} =
               CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)
    end
  end

  describe "lookup/2 (authentication-device view)" do
    test "returns the pending view for the approval UI" do
      %{auth_req_id: id} = issue(%{acr_values: ["urn:mace:phr"], binding_message: "S24R"})

      assert {:ok, view} = CIBA.lookup(Store, id)
      assert view.client_id == @client_id
      assert view.scope == ["openid", "accounts.read"]
      assert view.binding_message == "S24R"
      assert view.acr_values == ["urn:mace:phr"]
      assert view.subject == "usr_1"
      assert view.status == :pending
      assert view.delivery_mode == :poll
    end

    test "malformed input is rejected before the store lookup; unknown is :error" do
      assert {:error, :invalid_auth_req_id} = CIBA.lookup(Store, "bad id")
      assert :error = CIBA.lookup(Store, String.duplicate("a", 43))
    end
  end

  describe "grant context" do
    test "carries resource (RFC 8707) and falls back to the requested scope when approval grants none" do
      %{auth_req_id: id} = issue(%{}, %{resource: ["https://api.example.com"]})
      assert {:ok, _decision} = CIBA.approve(Store, id, %{subject: "usr_1"}, now: @now + 1)

      assert {:ok, %Grant{} = grant} = CIBA.redeem(Store, id, %{client_id: @client_id}, now: @now + 10)
      assert grant.resource == ["https://api.example.com"]
      assert grant.scope == ["openid", "accounts.read"]
    end
  end

  describe "grant_type/0 and error_status/1" do
    test "exposes the CIBA grant type URN" do
      assert CIBA.grant_type() == "urn:openid:params:grant-type:ciba"
    end

    test "maps the §13 backchannel authentication endpoint statuses" do
      assert CIBA.error_status(:invalid_client) == 401
      assert CIBA.error_status(:access_denied) == 403

      for error <- [
            :invalid_request,
            :invalid_scope,
            :expired_login_hint_token,
            :unknown_user_id,
            :unauthorized_client,
            :missing_user_code,
            :invalid_user_code,
            :invalid_binding_message
          ] do
        assert CIBA.error_status(error) == 400
      end
    end
  end
end
