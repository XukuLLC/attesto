defmodule Attesto.AuthorizationCodePropertyTest do
  @moduledoc false
  # Authorization-code lifecycle properties over the ETS reference store.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore
  alias Attesto.PKCE
  alias Attesto.Secret

  @scopes ~w(openid profile email documents.read documents.write offline_access)
  @verifier_chars Enum.concat([?A..?Z, ?a..?z, ?0..?9, [?-, ?., ?_, ?~]])

  setup do
    start_supervised!(CodeStore.ETS)
    CodeStore.ETS.reset()
    :ok
  end

  describe "issue/3 and redeem/4" do
    property "a valid code redeems once to the issued grant context" do
      check all(
              client_suffix <- suffix_generator(),
              subject_suffix <- suffix_generator(),
              redirect_path <- suffix_generator(),
              verifier <- verifier_generator(),
              scopes <- list_of(member_of(@scopes), max_length: 8),
              ttl <- integer(2..600),
              now <- integer(1_700_000_000..1_700_100_000),
              max_runs: 80
            ) do
        :ok = CodeStore.ETS.reset()
        {:ok, challenge} = PKCE.challenge(verifier)

        client_id = "oc_" <> client_suffix
        redirect_uri = "https://client.example/cb/" <> redirect_path
        subject = "usr_" <> subject_suffix
        scope = Enum.uniq(scopes)

        attrs = %{
          client_id: client_id,
          redirect_uri: redirect_uri,
          code_challenge: challenge,
          subject: subject,
          scope: scope,
          claims: %{"nonce" => "n-" <> subject_suffix}
        }

        params = %{client_id: client_id, redirect_uri: redirect_uri, code_verifier: verifier}

        assert {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, attrs, ttl: ttl, now: now)
        assert {:ok, %Grant{} = grant} = AuthorizationCode.redeem(CodeStore.ETS, code, params, now: now + ttl - 1)

        assert grant.client_id == client_id
        assert grant.redirect_uri == redirect_uri
        assert grant.subject == subject
        assert grant.scope == scope
        assert grant.claims == %{"nonce" => "n-" <> subject_suffix}

        assert {:error, :invalid_grant} =
                 AuthorizationCode.redeem(CodeStore.ETS, code, params, now: now + ttl - 1)
      end
    end

    property "any failed comparison leaves the code redeemable" do
      check all(
              verifier <- verifier_generator(),
              wrong_verifier <- verifier_generator(),
              wrong_verifier != verifier,
              failure <- member_of([:client, :redirect, :pkce, :dpop_missing, :dpop_wrong]),
              max_runs: 80
            ) do
        :ok = CodeStore.ETS.reset()
        {:ok, challenge} = PKCE.challenge(verifier)
        bound_jkt = Secret.hash("bound-key")

        attrs = %{
          client_id: "oc_client",
          redirect_uri: "https://client.example/cb",
          code_challenge: challenge,
          subject: "usr_subject",
          scope: ["openid"],
          dpop_jkt: bound_jkt
        }

        good_params = %{
          client_id: "oc_client",
          redirect_uri: "https://client.example/cb",
          code_verifier: verifier,
          dpop_jkt: bound_jkt
        }

        {bad_params, expected_error} =
          case failure do
            :client -> {%{good_params | client_id: "oc_other"}, :client_mismatch}
            :redirect -> {%{good_params | redirect_uri: "https://client.example/other"}, :redirect_uri_mismatch}
            :pkce -> {%{good_params | code_verifier: wrong_verifier}, :pkce_failed}
            :dpop_missing -> {Map.delete(good_params, :dpop_jkt), :dpop_proof_required}
            :dpop_wrong -> {%{good_params | dpop_jkt: Secret.hash("wrong-key")}, :dpop_binding_mismatch}
          end

        assert {:ok, code} = AuthorizationCode.issue(CodeStore.ETS, attrs, now: 1_000, ttl: 60)
        assert {:error, ^expected_error} = AuthorizationCode.redeem(CodeStore.ETS, code, bad_params, now: 1_001)
        assert {:ok, %Grant{}} = AuthorizationCode.redeem(CodeStore.ETS, code, good_params, now: 1_001)
      end
    end

    property "expiry boundary is strict: expires_at must be greater than now" do
      check all(
              verifier <- verifier_generator(),
              ttl <- integer(1..600),
              now <- integer(1_700_000_000..1_700_100_000),
              max_runs: 60
            ) do
        :ok = CodeStore.ETS.reset()
        {:ok, challenge} = PKCE.challenge(verifier)

        attrs = %{
          client_id: "oc_client",
          redirect_uri: "https://client.example/cb",
          code_challenge: challenge,
          subject: "usr_subject"
        }

        params = %{client_id: "oc_client", redirect_uri: "https://client.example/cb", code_verifier: verifier}

        assert {:ok, live_code} = AuthorizationCode.issue(CodeStore.ETS, attrs, now: now, ttl: ttl)
        assert {:ok, %Grant{}} = AuthorizationCode.redeem(CodeStore.ETS, live_code, params, now: now + ttl - 1)

        assert {:ok, expired_code} = AuthorizationCode.issue(CodeStore.ETS, attrs, now: now, ttl: ttl)
        assert {:error, :expired} = AuthorizationCode.redeem(CodeStore.ETS, expired_code, params, now: now + ttl)
        assert {:ok, _record} = CodeStore.ETS.read(Secret.hash(expired_code))
        assert {:error, :expired} = AuthorizationCode.redeem(CodeStore.ETS, expired_code, params, now: now + ttl)
      end
    end
  end

  defp verifier_generator do
    gen all(
          length <- integer(43..128),
          chars <- list_of(member_of(@verifier_chars), length: length)
        ) do
      List.to_string(chars)
    end
  end

  defp suffix_generator do
    gen all(chars <- list_of(member_of(Enum.concat([?a..?z, ?0..?9])), min_length: 1, max_length: 14)) do
      List.to_string(chars)
    end
  end
end
