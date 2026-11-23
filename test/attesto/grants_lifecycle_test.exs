defmodule Attesto.GrantsLifecycleTest do
  @moduledoc false
  # A live, end-to-end scenario test: drive the whole authorization-code +
  # refresh lifecycle the way a real client would, across every module
  # (PKCE -> AuthorizationCode -> Token mint/verify -> RefreshToken rotate
  # -> reuse). Scenario tests like this catch semantic bugs that per-module
  # unit tests rubber-stamp (e.g. a recoverable rotation error must not burn
  # the token).
  use ExUnit.Case, async: false

  alias Attesto.AuthorizationCode
  alias Attesto.AuthorizationCode.Grant
  alias Attesto.CodeStore
  alias Attesto.PKCE
  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Test.Factory
  alias Attesto.Token

  @verifier "lifecycle-verifier_unreserved.chars-aaaaaaaaaaaa~0"

  setup do
    start_supervised!(CodeStore.ETS)
    start_supervised!(RefreshStore.ETS)
    pem = Factory.rsa_pem()
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{config: Factory.config(pem), challenge: challenge}
  end

  # The host turns a redeemed grant's context into a verifiable user
  # access token.
  defp mint_access(config, subject, scope, sid) do
    {:ok, token} =
      Token.mint(config, %{
        kind: "user",
        sub: subject,
        scopes: scope,
        claims: %{"act" => "ac_1", "sid" => sid, "token_version" => 0}
      })

    {:ok, claims} = Token.verify(config, token.access_token)
    claims
  end

  test "full auth-code -> access -> refresh-rotate chain -> reuse kills the family", %{
    config: config,
    challenge: challenge
  } do
    # 1. Authorization endpoint mints a single-use, PKCE-bound code.
    {:ok, code} =
      AuthorizationCode.issue(CodeStore.ETS, %{
        client_id: "oc_app",
        redirect_uri: "https://app.example.com/cb",
        code_challenge: challenge,
        subject: "usr_42",
        scope: ["documents.read", "positions.read"],
        claims: %{"login_kind" => "passkey"}
      })

    # 2. Token endpoint redeems it (PKCE verifier checked, single use).
    assert {:ok, %Grant{} = grant} =
             AuthorizationCode.redeem(CodeStore.ETS, code, %{
               redirect_uri: "https://app.example.com/cb",
               code_verifier: @verifier,
               client_id: "oc_app"
             })

    assert grant.subject == "usr_42"
    assert grant.scope == ["documents.read", "positions.read"]
    assert grant.claims["login_kind"] == "passkey"

    # 3. The host mints (and we verify) the first access token from the grant.
    claims = mint_access(config, grant.subject, grant.scope, "sess_1")
    assert claims["sub"] == "usr_42"
    assert claims["scope"] == "documents.read positions.read"
    assert claims["principal_kind"] == "user"

    # 4. The host issues a refresh token carrying the grant context.
    {:ok, %{token: r0, family_id: fam, generation: 0}} =
      RefreshToken.issue(RefreshStore.ETS, %{
        subject: grant.subject,
        scope: grant.scope,
        client_id: grant.client_id
      })

    # 5. Rotate three times; each rotation mints a fresh access token and a
    #    new refresh token in the same family at the next generation.
    {r3, _} =
      Enum.reduce(1..3, {r0, 0}, fn gen, {token, _} ->
        # The refresh token is client-bound (it carries grant.client_id),
        # so each rotation presents the authenticated client.
        assert {:ok, %{token: next, family_id: ^fam, generation: ^gen, context: ctx}} =
                 RefreshToken.rotate(RefreshStore.ETS, token, client_id: "oc_app")

        assert ctx.subject == "usr_42"
        _claims = mint_access(config, ctx.subject, ctx.scope, "sess_#{gen}")
        {next, gen}
      end)

    # 6. The single-use code cannot be redeemed again.
    assert {:error, :invalid_grant} =
             AuthorizationCode.redeem(CodeStore.ETS, code, %{
               redirect_uri: "https://app.example.com/cb",
               code_verifier: @verifier,
               client_id: "oc_app"
             })

    # 7. An attacker replays an OLD refresh token (r0, long since rotated):
    #    reuse is detected and the whole family is revoked.
    #    The replay names the bound client: a different client presenting r0
    #    would be refused as a client mismatch without touching the family.
    assert {:error, :reuse_detected} = RefreshToken.rotate(RefreshStore.ETS, r0, client_id: "oc_app")

    # 8. The live token (r3) no longer rotates: the family is dead.
    assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, r3)
  end
end
