defmodule Attesto.KeystoreSigningProbeTest do
  use ExUnit.Case, async: true

  alias Attesto.{Key, Keystore}

  defmodule PEMStore do
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem, do: Process.get(:probe_pem)
    @impl true
    def verification_pems, do: [Process.get(:probe_public)]
  end

  defmodule ExternalStore do
    @behaviour Attesto.Keystore
    @behaviour Attesto.Signer

    @impl true
    def signing_jwk, do: Process.get(:probe_public_jwk)
    @impl true
    def verification_pems, do: [Process.get(:probe_public)]
    @impl true
    def sign(input, "RS256") do
      Process.put(:probe_calls, Process.get(:probe_calls, 0) + 1)

      case Process.get(:probe_failure) do
        nil -> {:ok, :public_key.sign(input, :sha256, Process.get(:probe_private))}
        :error -> {:error, "provider private detail"}
        :throw -> throw("provider private detail")
      end
    end
  end

  test "signs and verifies with published PEM keys" do
    for params <- [{:rsa, 2048}, {:ec, "P-256"}, {:okp, :Ed25519}] do
      jwk = JOSE.JWK.generate_key(params)
      Process.put(:probe_pem, jwk |> JOSE.JWK.to_pem() |> elem(1))
      Process.put(:probe_public, jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem() |> elem(1))
      assert %{status: :healthy, issues: []} = Keystore.rotation_health(PEMStore)
    end
  end

  test "inconsistent RSA private components are invalid despite matching public thumbprints" do
    original = JOSE.JWK.generate_key({:rsa, 2048})
    other = JOSE.JWK.generate_key({:rsa, 2048})
    {_, fields} = JOSE.JWK.to_map(original)
    {_, other_fields} = JOSE.JWK.to_map(other)
    bad = JOSE.JWK.from_map(Map.put(fields, "n", other_fields["n"]))
    Process.put(:probe_pem, bad |> JOSE.JWK.to_pem() |> elem(1))
    Process.put(:probe_public, bad |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem() |> elem(1))
    assert Key.kid(PEMStore.signing_pem()) == Key.kid(hd(PEMStore.verification_pems()))
    assert %{status: :invalid, issues: issues} = Keystore.rotation_health(PEMStore)
    assert :signing_key_mismatch in issues
  end

  test "external custody is exercised once and wrong keys or signer failures are invalid" do
    key = JOSE.JWK.generate_key({:rsa, 2048})
    Process.put(:probe_public_jwk, Key.public_map(key))
    Process.put(:probe_public, key |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem() |> elem(1))
    Process.put(:probe_private, key |> JOSE.JWK.to_key() |> elem(1))
    assert %{status: :healthy, issues: []} = Keystore.rotation_health(ExternalStore)
    assert Process.get(:probe_calls) == 1

    other = JOSE.JWK.generate_key({:rsa, 2048})
    Process.put(:probe_private, other |> JOSE.JWK.to_key() |> elem(1))

    for failure <- [nil, :error, :throw] do
      Process.put(:probe_failure, failure)
      assert %{status: :invalid, issues: [:signing_key_mismatch]} = Keystore.rotation_health(ExternalStore)
    end

    assert Process.get(:probe_calls) == 4
  end
end
