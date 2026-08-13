defmodule Attesto.KeystoreRotationHealthTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias __MODULE__.RotationKeystore
  alias Attesto.{Key, Keystore, Token}
  alias Attesto.Test.Factory

  setup do
    on_exit(fn -> Application.delete_env(:attesto, RotationKeystore) end)
    :ok
  end

  test "reports a healthy overlap and proves tokens under both keys verify" do
    old_pem = Factory.rsa_pem()
    new_pem = Factory.rsa_pem()
    now = DateTime.from_unix!(1_800_000_000)

    install(old_pem, [old_pem], %{})
    old_config = config()
    {:ok, %{access_token: old_token}} = Token.mint(old_config, principal("old"))

    install(new_pem, [new_pem, old_pem], %{
      Key.kid(old_pem) => %{not_after: DateTime.add(now, 86_400, :second)},
      Key.kid(new_pem) => %{not_after: DateTime.add(now, 31_536_000, :second)}
    })

    health = Keystore.rotation_health(RotationKeystore, now: now, expiry_warning_seconds: 3600)
    assert health.status == :healthy
    assert health.overlap?
    assert health.key_count == 2
    assert health.signing_kid == Key.kid(new_pem)
    assert Enum.count(health.keys, & &1.current?) == 1

    {:ok, %{access_token: new_token}} = Token.mint(config(), principal("new"))
    assert {:ok, _claims} = Token.verify(config(), old_token)
    assert {:ok, _claims} = Token.verify(config(), new_token)
  end

  test "fails health when the current signing key is absent from verification" do
    old_pem = Factory.rsa_pem()
    new_pem = Factory.rsa_pem()
    install(new_pem, [old_pem], %{})

    health = Keystore.rotation_health(RotationKeystore)
    assert health.status == :invalid
    assert :signing_key_not_published in health.issues
  end

  test "surfaces expiring and expired verification keys" do
    current = Factory.rsa_pem()
    expired = Factory.rsa_pem()
    now = DateTime.from_unix!(1_800_000_000)

    install(current, [current, expired], %{
      Key.kid(current) => %{not_after: DateTime.add(now, 300, :second)},
      Key.kid(expired) => %{not_after: DateTime.add(now, -1, :second)}
    })

    health = Keystore.rotation_health(RotationKeystore, now: now, expiry_warning_seconds: 600)
    assert health.status == :warning
    assert :expiring_signing_key in health.issues
    assert :expired_verification_key in health.issues
    assert Enum.find(health.keys, & &1.current?).state == :expiring
    assert Enum.find(health.keys, &(&1.kid == Key.kid(expired))).state == :expired
  end

  test "an expired current signing key is invalid and distinguished from stale overlap" do
    current = Factory.rsa_pem()
    now = DateTime.from_unix!(1_800_000_000)

    install(current, [current], %{
      Key.kid(current) => %{not_after: DateTime.add(now, -1, :second)}
    })

    health = Keystore.rotation_health(RotationKeystore, now: now)
    assert health.status == :invalid
    assert :expired_signing_key in health.issues
    refute :expired_verification_key in health.issues
  end

  test "unknown metadata kids are invalid instead of silently ignored" do
    current = Factory.rsa_pem()
    install(current, [current], %{"stale-or-typo" => %{not_after: 1_900_000_000}})

    health = Keystore.rotation_health(RotationKeystore)
    assert health.status == :invalid
    assert health.unknown_metadata_kids == ["stale-or-typo"]
    assert :unknown_verification_key_metadata in health.issues
  end

  test "rejects atom metadata keys and bare DateTime metadata values" do
    current = Factory.rsa_pem()
    kid = Key.kid(current)

    install(current, [current], %{String.to_atom(kid) => %{not_after: 1_900_000_000}})

    assert_raise ArgumentError, ~r/keys must be non-empty RFC 7638 kid strings/, fn ->
      Keystore.rotation_health(RotationKeystore)
    end

    install(current, [current], %{kid => DateTime.utc_now()})

    assert_raise ArgumentError, ~r/must be a map/, fn ->
      Keystore.rotation_health(RotationKeystore)
    end
  end

  test "rejects misspelled and duplicate expiry fields instead of disabling the check" do
    current = Factory.rsa_pem()
    kid = Key.kid(current)

    install(current, [current], %{kid => %{not_aftr: 1_900_000_000}})

    assert_raise ArgumentError, ~r/unsupported keys/, fn ->
      Keystore.rotation_health(RotationKeystore)
    end

    install(current, [current], %{
      kid => %{:not_after => 1_900_000_000, "not_after" => 1_900_000_001}
    })

    assert_raise ArgumentError, ~r/must not contain both/, fn ->
      Keystore.rotation_health(RotationKeystore)
    end
  end

  defp install(signing_pem, verification_pems, metadata) do
    Application.put_env(:attesto, RotationKeystore,
      signing_pem: signing_pem,
      verification_pems: verification_pems,
      metadata: metadata
    )
  end

  defp config do
    Attesto.Config.new(
      issuer: "https://issuer.example.com",
      audience: "https://api.example.com",
      keystore: RotationKeystore,
      principal_kinds: [
        Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
      ]
    )
  end

  defp principal(suffix) do
    %{
      kind: "client",
      sub: "oc_#{suffix}",
      scopes: ["read"],
      claims: %{"client_id" => suffix}
    }
  end

  defmodule RotationKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: config() |> Keyword.fetch!(:signing_pem)

    @impl true
    def verification_pems, do: config() |> Keyword.fetch!(:verification_pems)

    @impl true
    def verification_key_metadata, do: config() |> Keyword.fetch!(:metadata)

    defp config, do: Application.fetch_env!(:attesto, __MODULE__)
  end
end
