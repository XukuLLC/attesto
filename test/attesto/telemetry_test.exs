defmodule Attesto.TelemetryTest do
  @moduledoc false
  # The event names and metadata keys asserted here are public API: a host
  # attaches to them and routes them to a pager or a SIEM. Renaming one, or
  # dropping a documented key, breaks that host silently at runtime - there is
  # no compile-time link between an emitter and a handler. These tests are the
  # link.
  use ExUnit.Case, async: false

  alias Attesto.RefreshStore
  alias Attesto.RefreshToken
  alias Attesto.Telemetry
  alias Attesto.Test.Factory
  alias Attesto.Token

  setup context do
    handler = "attesto-telemetry-test-#{inspect(context.test)}"
    test_pid = self()

    :ok =
      :telemetry.attach_many(
        handler,
        Telemetry.events(),
        fn event, measurements, metadata, _cfg ->
          send(test_pid, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)
    start_supervised!(RefreshStore.ETS)
    :ok
  end

  describe "events/0" do
    test "lists every event the library emits, for attach_many/4" do
      assert Telemetry.events() == [
               [:attesto, :refresh_token, :reuse_detected],
               [:attesto, :dpop, :replay_detected],
               [:attesto, :token, :sender_constraint_mismatch]
             ]
    end
  end

  describe "[:attesto, :refresh_token, :reuse_detected]" do
    test "fires when a rotated token is presented again, carrying the revoked family" do
      {:ok, %{token: t0}} =
        RefreshToken.issue(RefreshStore.ETS, %{
          subject: "usr_77",
          client_id: "oc_client",
          scope: ["documents.read"]
        })

      # Rotation is fail-closed on the client binding: a token issued with a
      # `client_id` must present a matching one.
      {:ok, _successor} = RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_client")

      # Outside the idempotency window the reuse is a captured-token signal.
      assert {:error, :reuse_detected} =
               RefreshToken.rotate(RefreshStore.ETS, t0, client_id: "oc_client", now: future())

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], measurements, metadata}

      assert is_integer(measurements.system_time)
      assert is_binary(metadata.family_id)
      assert metadata.client_id == "oc_client"
      assert metadata.subject == "usr_77"
    end

    test "an ordinary successful rotation emits nothing" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_78"})
      {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0)

      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _}
    end

    # Routine refusals must not be events, or the signal above drowns.
    test "an unknown token emits nothing" do
      assert {:error, :invalid_grant} = RefreshToken.rotate(RefreshStore.ETS, "no-such-token")

      refute_received {:telemetry, _event, _measurements, _metadata}
    end

    # Three paths conclude "presented twice": the initial read finds an
    # already-consumed token, the atomic `consume` reports `{:reuse, _}`
    # against a concurrent rotation, or our own claim wins and then finds the
    # family revoked underneath it. The first is a lone late retry; the other
    # two are a live race - the shape an attacker racing the legitimate client
    # actually produces, and the two that were silent.
    #
    # A real race cannot test this: whether any racer reaches the concurrent
    # branch is timing-dependent, and an emission from the initial-read path
    # looks identical from outside. These stores force each branch instead.
    defmodule ReuseOnConsumeStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @entry %{
        token_hash: "hash",
        family_id: "fam_concurrent",
        generation: 0,
        data: %{subject: "usr_concurrent", client_id: "oc_racer", scope: [], resource: [], claims: %{}, dpop_jkt: nil},
        expires_at: 4_102_444_800,
        consumed: false,
        consumed_at: nil,
        successor: nil
      }

      def entry, do: @entry

      @impl true
      def get(_hash), do: {:ok, @entry}
      @impl true
      def consume(_hash, _opts), do: {:reuse, @entry}
      @impl true
      def revoke_family(_family_id), do: :ok
      @impl true
      def insert(_entry), do: :ok
      @impl true
      def remember_successor(_hash, _successor, _opts), do: :ok
    end

    defmodule FamilyRevokedStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @entry ReuseOnConsumeStore.entry()

      @impl true
      def get(_hash), do: {:ok, @entry}
      @impl true
      def consume(_hash, _opts), do: {:ok, @entry}
      @impl true
      def revoke_family(_family_id), do: :ok
      @impl true
      def insert(_entry), do: {:error, :family_revoked}
      @impl true
      def remember_successor(_hash, _successor, _opts), do: :ok
    end

    test "a concurrent claim losing to `consume` emits" do
      assert {:error, :reuse_detected} = RefreshToken.rotate(ReuseOnConsumeStore, "presented", client_id: "oc_racer")

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}
      assert metadata.family_id == "fam_concurrent"
      assert metadata.subject == "usr_concurrent"
      assert metadata.client_id == "oc_racer"
    end

    # This double reproduces the RETURN value of a revoked family but not its
    # cause, and the cause is the whole question: `revoke_family/1` is also what
    # an ordinary RFC 7009 revocation or a logout calls, so a family can be
    # revoked mid-rotation by a token presented exactly once. The library cannot
    # tell the two apart from this branch, so it denies without accusing.
    test "winning the claim and then finding the family revoked denies WITHOUT alleging reuse" do
      # `:grant_revoked`, not `:reuse_detected`: the return says what is known
      # (the family is gone) rather than what is not (why).
      assert {:error, :grant_revoked} = RefreshToken.rotate(FamilyRevokedStore, "presented", client_id: "oc_racer")

      refute_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, _},
                      "a concurrent logout must not page someone about a stolen credential"
    end

    test "metadata carries no credential material" do
      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_79"})
      {:ok, %{token: successor}} = RefreshToken.rotate(RefreshStore.ETS, t0)
      {:error, :reuse_detected} = RefreshToken.rotate(RefreshStore.ETS, t0, now: future())

      assert_received {:telemetry, [:attesto, :refresh_token, :reuse_detected], _, metadata}

      encoded = inspect(metadata)
      refute encoded =~ t0, "the presented refresh token must not appear in metadata"
      refute encoded =~ successor, "the successor token must not appear in metadata"
    end
  end

  describe "[:attesto, :dpop, :replay_detected]" do
    test "fires when the replay check refuses a jti" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {proof, _jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: "https://api.example.com/x")

      assert {:error, :replay} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example.com/x",
                 replay_check: fn _jti, _ttl -> {:error, :replay} end
               )

      assert_received {:telemetry, [:attesto, :dpop, :replay_detected], measurements, metadata}
      assert is_integer(measurements.system_time)
      assert is_binary(metadata.jti)
    end

    test "a first-use proof emits nothing" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {proof, _jkt} = Factory.dpop_proof(jwk: jwk, htm: "GET", htu: "https://api.example.com/x")

      assert {:ok, _} =
               Attesto.DPoP.verify_proof(proof,
                 http_method: "GET",
                 http_uri: "https://api.example.com/x",
                 replay_check: fn _jti, _ttl -> :ok end
               )

      refute_received {:telemetry, [:attesto, :dpop, :replay_detected], _, _}
    end
  end

  describe "[:attesto, :token, :sender_constraint_mismatch]" do
    setup do
      {:ok, config: Factory.config(Factory.rsa_pem())}
    end

    test "fires when a DPoP-bound token is presented under the wrong key", %{config: config} do
      bound = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      other = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))

      {:ok, %{access_token: token}} =
        Token.mint(config, principal(), dpop_jkt: bound)

      assert {:error, :dpop_binding_mismatch} = Token.verify(config, token, dpop_jkt: other)

      assert_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _measurements, metadata}
      assert metadata.binding == :dpop
      assert metadata.reason == :dpop_binding_mismatch
      assert metadata.client_id == "oc_abc"
    end

    # The event is documented as evidence a token has left its holder, so it
    # must not be ringable by someone who merely holds ANY sender-bound token
    # from this issuer. Presenting one under a second key at a resource whose
    # audience policy would refuse it anyway must be refused on the audience,
    # silently - otherwise the alarm is free to ring, and repeatedly, since a
    # failed verification never claims the proof's `jti`.
    test "a token this resource would refuse on audience does not ring the alarm", %{config: config} do
      bound = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      other = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      elsewhere = "https://elsewhere.example/api"

      {:ok, %{access_token: token}} =
        Token.mint(config, principal(), dpop_jkt: bound, audience: elsewhere)

      # This resource trusts a different audience, and is presented the token
      # under the wrong key: both checks would fail.
      assert {:error, reason} =
               Token.verify(config, token,
                 dpop_jkt: other,
                 trusted_audiences: fn _claims -> ["https://this-resource.example/api"] end
               )

      assert reason == :invalid_audience,
             "audience must be decided before the binding check that reports"

      refute_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _, _}
    end

    test "an unbound token verified normally emits nothing", %{config: config} do
      {:ok, %{access_token: token}} = Token.mint(config, principal())

      assert {:ok, _claims} = Token.verify(config, token)

      refute_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _, _}
    end

    test "metadata carries no token material", %{config: config} do
      bound = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))
      other = JOSE.JWK.thumbprint(JOSE.JWK.generate_key({:ec, "P-256"}))

      {:ok, %{access_token: token}} = Token.mint(config, principal(), dpop_jkt: bound)
      {:error, :dpop_binding_mismatch} = Token.verify(config, token, dpop_jkt: other)

      assert_received {:telemetry, [:attesto, :token, :sender_constraint_mismatch], _, metadata}
      refute inspect(metadata) =~ token
    end
  end

  # `:telemetry.execute/3` catches a raising handler, detaches it, and logs, so
  # the refusal is never taken down by a bad handler. Attesto adds no catch of
  # its own: one would also swallow a dispatcher failure, and silently losing an
  # event whose purpose is to say a credential may be stolen is worse than
  # failing loudly - a missing event leaves nothing to notice later.
  describe "a failing handler does not change the outcome" do
    test "reuse detection still returns :reuse_detected" do
      :telemetry.attach(
        "attesto-telemetry-raiser",
        [:attesto, :refresh_token, :reuse_detected],
        fn _e, _m, _md, _c -> raise "handler blew up" end,
        nil
      )

      on_exit(fn -> :telemetry.detach("attesto-telemetry-raiser") end)

      {:ok, %{token: t0}} = RefreshToken.issue(RefreshStore.ETS, %{subject: "usr_80"})
      {:ok, _} = RefreshToken.rotate(RefreshStore.ETS, t0)

      assert {:error, :reuse_detected} = RefreshToken.rotate(RefreshStore.ETS, t0, now: future())
    end
  end

  defp future, do: DateTime.add(DateTime.utc_now(), 3600, :second)

  defp principal do
    %{kind: "client", sub: "oc_abc", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc"}}
  end
end
