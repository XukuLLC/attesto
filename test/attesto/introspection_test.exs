defmodule Attesto.IntrospectionTest do
  @moduledoc false
  # Factory.config installs key material into the application env.
  use ExUnit.Case, async: false

  alias Attesto.Introspection
  alias Attesto.Secret
  alias Attesto.Test.Factory
  alias Attesto.Token

  setup do
    {:ok, config: Factory.config(Factory.rsa_pem())}
  end

  defp client_principal(overrides \\ %{}) do
    Map.merge(
      %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
      overrides
    )
  end

  describe "introspect/3 - access tokens" do
    test "an active access token is described with the RFC 7662 members", %{config: config} do
      now = 1_700_000_000

      {:ok, %{access_token: jwt}} =
        Token.mint(config, client_principal(%{scopes: ["documents.read", "positions.read"]}), now: now)

      response = Introspection.introspect(config, jwt, now: now)

      assert response["active"] == true
      assert response["scope"] == "documents.read positions.read"
      assert response["sub"] == "oc_abc123"
      assert response["client_id"] == "oc_abc123"
      assert response["iss"] == config.issuer
      assert response["aud"] == config.audience
      assert is_integer(response["exp"])
      assert is_integer(response["iat"])
      assert is_binary(response["jti"])
      assert response["token_type"] == "Bearer"
    end

    test "an expired access token is inactive (no existence oracle)", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      # Introspect well after expiry.
      assert Introspection.introspect(config, jwt, now: now + 100_000) == %{"active" => false}
    end

    test "a garbage or forged token is inactive", %{config: config} do
      assert Introspection.introspect(config, "not-a-jwt", now: 1_700_000_000) == %{"active" => false}
      assert Introspection.introspect(config, "a.b.c", now: 1_700_000_000) == %{"active" => false}
    end

    test "a sender-constrained token is active and echoes cnf with token_type DPoP", %{config: config} do
      now = 1_700_000_000
      jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

      {:ok, %{access_token: jwt}} =
        Token.mint(config, client_principal(), now: now, dpop_jkt: jkt)

      # No proof key is presented at introspection - activeness must not depend
      # on the confirmation binding.
      response = Introspection.introspect(config, jwt, now: now)

      assert response["active"] == true
      assert response["token_type"] == "DPoP"
      assert response["cnf"] == %{"jkt" => jkt}
    end

    test "a refresh-typ JWT is inactive (access-token introspection rejects typ != access)", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: refresh_jwt}} = Token.mint(config, client_principal(), now: now, typ: "refresh")

      assert Introspection.introspect(config, refresh_jwt, now: now) == %{"active" => false}
    end

    test "a token for a different audience is inactive", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      # A config whose audience differs from the token's aud must not accept it,
      # matching Token.verify/3's invalid_audience rejection.
      other = Factory.config(config.keystore.signing_pem(), audience: "https://other.example.com/")

      assert Introspection.introspect(other, jwt, now: now) == %{"active" => false}
    end

    test "an RFC 8707 resource-audienced token is active only when explicitly trusted", %{
      config: config
    } do
      now = 1_700_000_000
      resource = "https://resource.example/mcp"

      {:ok, %{access_token: jwt}} =
        Token.mint(config, client_principal(), now: now, audience: resource)

      assert Introspection.introspect(config, jwt, now: now) == %{"active" => false}

      response =
        Introspection.introspect(config, jwt,
          now: now,
          trusted_audiences: [config.audience, resource]
        )

      assert response["active"] == true
      assert response["aud"] == resource

      assert Introspection.introspect(config, jwt,
               now: now,
               trusted_audiences: [config.audience, "https://other.example/mcp"]
             ) == %{"active" => false}
    end

    test "trusted audiences fail closed for malformed policy and partially untrusted arrays", %{
      config: config
    } do
      now = 1_700_000_000
      trusted = "https://resource.example/a"
      untrusted = "https://resource.example/not-allowed"

      {:ok, %{access_token: array_jwt}} =
        Token.mint(config, client_principal(),
          now: now,
          audience: [trusted, untrusted]
        )

      assert Introspection.introspect(config, array_jwt,
               now: now,
               trusted_audiences: [config.audience, trusted]
             ) == %{"active" => false}

      {:ok, %{access_token: scalar_jwt}} =
        Token.mint(config, client_principal(), now: now, audience: trusted)

      for malformed <- [[], [trusted, 123], [trusted, ""], trusted] do
        assert Introspection.introspect(config, scalar_jwt,
                 now: now,
                 trusted_audiences: malformed
               ) == %{"active" => false}
      end

      assert Introspection.introspect(config, scalar_jwt,
               now: now,
               trusted_audiences: fn claims ->
                 assert claims["client_id"] == "oc_abc123"
                 [config.audience, trusted]
               end
             )["active"] == true

      assert Introspection.introspect(config, scalar_jwt,
               now: now,
               trusted_audiences: fn _claims -> raise "broken policy" end
             ) == %{"active" => false}
    end
  end

  describe "introspect/3 - :authorize caller policy (RFC 7662 §4 / RFC 9701 §5)" do
    test "an authorize predicate that accepts leaves the active response intact", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      response = Introspection.introspect(config, jwt, now: now, authorize: fn _resp -> true end)

      assert response["active"] == true
      assert response["sub"] == "oc_abc123"
    end

    test "an authorize predicate that rejects downgrades to inactive (no leak)", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      assert Introspection.introspect(config, jwt, now: now, authorize: fn _resp -> false end) ==
               %{"active" => false}
    end

    test "the predicate sees the response (e.g. to match aud against the caller)", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      authorize = fn resp -> resp["aud"] == config.audience end
      assert Introspection.introspect(config, jwt, now: now, authorize: authorize)["active"] == true

      authorize_other = fn resp -> resp["aud"] == "https://not-the-caller.example" end

      assert Introspection.introspect(config, jwt, now: now, authorize: authorize_other) ==
               %{"active" => false}
    end

    test "a raising predicate fails closed to inactive", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      assert Introspection.introspect(config, jwt, now: now, authorize: fn _ -> raise "boom" end) ==
               %{"active" => false}
    end

    test "a throwing or exiting predicate also fails closed to inactive", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      for authorize <- [
            fn _ -> throw({:private, "authorize-throw-sentinel"}) end,
            fn _ -> exit({:private, "authorize-exit-sentinel"}) end
          ] do
        assert Introspection.introspect(config, jwt, now: now, authorize: authorize) ==
                 %{"active" => false}
      end
    end

    test "a non-boolean return value fails closed to inactive", %{config: config} do
      now = 1_700_000_000
      {:ok, %{access_token: jwt}} = Token.mint(config, client_principal(), now: now)

      assert Introspection.introspect(config, jwt, now: now, authorize: fn _ -> :yes end) ==
               %{"active" => false}
    end

    test "the predicate is not consulted for an already-inactive token", %{config: config} do
      # A forged token is inactive regardless; the predicate must not run (there
      # is nothing to authorize), so a raising predicate still yields inactive
      # rather than masking a would-be leak.
      assert Introspection.introspect(config, "not-a-jwt",
               now: 1_700_000_000,
               authorize: fn _ -> raise "should not be called" end
             ) == %{"active" => false}
    end
  end

  describe "introspect/3 - refresh tokens" do
    defmodule StubRefreshStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def get(hash) do
        case :persistent_term.get({__MODULE__, hash}, :error) do
          :error -> :error
          entry -> {:ok, entry}
        end
      end

      @impl true
      def insert(_entry), do: :ok
      @impl true
      def rotate(_hash, _child, _successor, _opts), do: :error
      @impl true
      def revoke_family(_family_id), do: :ok

      def put(token, entry) do
        token_hash = Secret.hash(token)

        entry =
          entry
          |> Map.put_new(:token_hash, token_hash)
          |> Map.put_new(:generation, 0)
          |> Map.put_new(:consumed_at, if(Map.get(entry, :consumed) == true, do: 1))
          |> Map.put_new(:successor, nil)

        :persistent_term.put({__MODULE__, token_hash}, entry)
      end
    end

    defmodule FaultingRefreshStore do
      @moduledoc false
      @behaviour Attesto.RefreshStore

      @impl true
      def get(_hash) do
        case Process.get({__MODULE__, :fault}) do
          {:return, value} -> value
          {:raise, value} -> raise RuntimeError, value
          {:throw, value} -> throw(value)
          {:exit, value} -> exit(value)
        end
      end

      @impl true
      def insert(_entry), do: :ok
      @impl true
      def rotate(_hash, _child, _successor, _opts), do: :error
      @impl true
      def revoke_family(_family_id), do: :ok
    end

    setup context do
      handler = "attesto-introspection-store-failure-#{inspect(context.test)}"
      test_pid = self()

      :ok =
        :telemetry.attach(
          handler,
          [:attesto, :introspection, :refresh_store_failed],
          &__MODULE__.handle_introspection_store_failure/4,
          test_pid
        )

      on_exit(fn -> :telemetry.detach(handler) end)
      :ok
    end

    defp introspect_refresh(config, token, now) do
      Introspection.introspect(config, token,
        now: now,
        refresh_store: StubRefreshStore,
        token_type_hint: "refresh_token"
      )
    end

    test "a stored, unconsumed, unexpired refresh token is active (minimal members)", %{config: config} do
      now = 1_700_000_000

      StubRefreshStore.put("refresh-xyz", %{
        family_id: "fam-1",
        expires_at: now + 1000,
        consumed: false,
        data: %{}
      })

      assert introspect_refresh(config, "refresh-xyz", now) == %{"active" => true, "exp" => now + 1000}
    end

    test "a consumed (rotated) refresh token is inactive even before it expires", %{config: config} do
      now = 1_700_000_000

      StubRefreshStore.put("refresh-consumed", %{
        family_id: "fam-1",
        expires_at: now + 1000,
        consumed: true,
        data: %{}
      })

      assert introspect_refresh(config, "refresh-consumed", now) == %{"active" => false}
    end

    test "an expired refresh token is inactive", %{config: config} do
      now = 1_700_000_000

      StubRefreshStore.put("refresh-expired", %{
        family_id: "fam-1",
        expires_at: now - 1,
        consumed: false,
        data: %{}
      })

      assert introspect_refresh(config, "refresh-expired", now) == %{"active" => false}
    end

    test "an unknown refresh token is inactive", %{config: config} do
      assert Introspection.introspect(config, "nope",
               now: 1_700_000_000,
               refresh_store: StubRefreshStore
             ) == %{"active" => false}

      refute_received {:introspection_store_failure, _, _, _}
    end

    test "a malformed record missing :consumed is inactive (fail closed)", %{config: config} do
      now = 1_700_000_000
      StubRefreshStore.put("refresh-malformed", %{family_id: "fam-1", expires_at: now + 1000, data: %{}})

      assert introspect_refresh(config, "refresh-malformed", now) == %{"active" => false}

      assert_received {:introspection_store_failure, [:attesto, :introspection, :refresh_store_failed], measurements,
                       %{operation: :get, reason: :store_contract_violation}}

      assert is_integer(measurements.system_time)
    end

    test "malformed security context is inactive instead of degrading to bearer or minimal", %{config: config} do
      now = 1_700_000_000

      for {suffix, data} <- [
            {"scope", %{subject: "user-42", scope: ["openid", :invalid]}},
            {"dpop", %{subject: "user-42", scope: [], dpop_jkt: "invalid"}},
            {"subject", %{subject: "", scope: []}},
            {"resource", %{subject: "user-42", scope: [], resource: [""]}},
            {"claims", %{subject: "user-42", scope: [], claims: []}},
            {"conflict", %{"subject" => "different", subject: "user-42", scope: []}}
          ] do
        token = "refresh-malformed-#{suffix}"

        StubRefreshStore.put(token, %{
          family_id: "fam-1",
          expires_at: now + 1000,
          consumed: false,
          data: data
        })

        assert introspect_refresh(config, token, now) == %{"active" => false}

        assert_received {:introspection_store_failure, [:attesto, :introspection, :refresh_store_failed], _,
                         %{operation: :get, reason: :store_contract_violation}}
      end
    end

    test "a row for another token hash is inactive and reported as a store contract violation", %{config: config} do
      now = 1_700_000_000

      StubRefreshStore.put("refresh-wrong-row", %{
        token_hash: Secret.hash("different-token"),
        family_id: "fam-1",
        generation: 0,
        expires_at: now + 1000,
        consumed: false,
        data: %{}
      })

      assert introspect_refresh(config, "refresh-wrong-row", now) == %{"active" => false}

      assert_received {:introspection_store_failure, [:attesto, :introspection, :refresh_store_failed], _,
                       %{operation: :get, reason: :store_contract_violation}}
    end

    test "an unexpected store return stays inactive and emits no callback data", %{config: config} do
      Process.put(
        {FaultingRefreshStore, :fault},
        {:return, {:unexpected, "refresh-store-private-return"}}
      )

      assert introspect_fault(config) == %{"active" => false}

      assert_received {:introspection_store_failure, [:attesto, :introspection, :refresh_store_failed], _,
                       %{operation: :get, reason: :store_contract_violation} = metadata}

      refute inspect(metadata) =~ "refresh-store-private-return"
    end

    test "store raise, throw, and exit stay inactive with bounded operational reasons", %{config: config} do
      for {fault, expected_reason, private_value} <- [
            {:raise, :store_raised, "refresh-store-private-raise"},
            {:throw, :store_threw, {:refresh_store_throw, "refresh-store-private-throw"}},
            {:exit, :store_exited, {:refresh_store_exit, "refresh-store-private-exit"}}
          ] do
        Process.put({FaultingRefreshStore, :fault}, {fault, private_value})

        assert introspect_fault(config) == %{"active" => false}

        assert_received {:introspection_store_failure, [:attesto, :introspection, :refresh_store_failed], _,
                         %{operation: :get, reason: ^expected_reason} = metadata}

        refute inspect(metadata) =~ "refresh-store-private"
      end
    end

    test "surfaces sub/scope/client_id from the stored data (RFC 7662 §2.2)", %{config: config} do
      now = 1_700_000_000

      StubRefreshStore.put("refresh-rich", %{
        family_id: "fam-1",
        expires_at: now + 1000,
        consumed: false,
        data: %{subject: "user-42", scope: ["openid", "documents.read"], client_id: "oc_abc123"}
      })

      response = introspect_refresh(config, "refresh-rich", now)

      assert response["active"] == true
      assert response["sub"] == "user-42"
      assert response["scope"] == "openid documents.read"
      assert response["client_id"] == "oc_abc123"
      refute Map.has_key?(response, "cnf")
    end

    test "echoes the DPoP binding as cnf/token_type for a sender-constrained refresh token", %{
      config: config
    } do
      now = 1_700_000_000
      jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

      StubRefreshStore.put("refresh-dpop", %{
        family_id: "fam-1",
        expires_at: now + 1000,
        consumed: false,
        data: %{subject: "user-42", scope: [], client_id: "oc_abc123", dpop_jkt: jkt}
      })

      response = introspect_refresh(config, "refresh-dpop", now)

      assert response["cnf"] == %{"jkt" => jkt}
      assert response["token_type"] == "DPoP"
    end

    test "reads string-keyed data from a custom store too", %{config: config} do
      now = 1_700_000_000

      StubRefreshStore.put("refresh-stringkeys", %{
        family_id: "fam-1",
        expires_at: now + 1000,
        consumed: false,
        data: %{"subject" => "user-99", "client_id" => "oc_xyz"}
      })

      response = introspect_refresh(config, "refresh-stringkeys", now)

      assert response["sub"] == "user-99"
      assert response["client_id"] == "oc_xyz"
    end

    test "an :authorize policy can make a per-token decision for refresh tokens", %{config: config} do
      now = 1_700_000_000

      StubRefreshStore.put("refresh-authz", %{
        family_id: "fam-1",
        expires_at: now + 1000,
        consumed: false,
        data: %{subject: "user-42", scope: [], client_id: "oc_abc123"}
      })

      # The caller is only entitled to its own client's refresh tokens.
      allow = fn response -> response["client_id"] == "oc_abc123" end
      deny = fn response -> response["client_id"] == "someone-else" end

      assert Introspection.introspect(config, "refresh-authz",
               now: now,
               refresh_store: StubRefreshStore,
               token_type_hint: "refresh_token",
               authorize: allow
             )["active"] == true

      assert Introspection.introspect(config, "refresh-authz",
               now: now,
               refresh_store: StubRefreshStore,
               token_type_hint: "refresh_token",
               authorize: deny
             ) == %{"active" => false}
    end

    defp introspect_fault(config) do
      Introspection.introspect(config, "opaque-refresh-token",
        now: 1_700_000_000,
        refresh_store: FaultingRefreshStore,
        token_type_hint: "refresh_token"
      )
    end
  end

  @doc false
  def handle_introspection_store_failure(event, measurements, metadata, test_pid) do
    send(test_pid, {:introspection_store_failure, event, measurements, metadata})
  end
end
