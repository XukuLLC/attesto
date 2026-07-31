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

  # A handler that raises is detached by :telemetry itself; what must not
  # happen is the refusal turning into a crash for the caller.
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
