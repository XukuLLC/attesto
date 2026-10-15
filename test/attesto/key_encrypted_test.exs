defmodule Attesto.KeyEncryptedTest do
  @moduledoc false
  # Behaviour of `Attesto.Key` against a *passphrase-encrypted* RSA private
  # PEM (one carrying `Proc-Type: 4,ENCRYPTED` / `DEK-Info:` headers)
  # probed WITHOUT supplying the passphrase. Attesto.Key takes a plain PEM
  # string and has no passphrase parameter, so an encrypted PEM is simply
  # un-decodable material. These tests pin the documented uniform error.
  #
  # Attesto.Key is pure, so async: true is safe.
  use ExUnit.Case, async: true

  alias Attesto.Key

  # A passphrase-encrypted RSA private PEM. On OTP 28
  # `:public_key.pem_entry_encode/3` requires the passphrase as a charlist
  # (a binary raises FunctionClauseError), hence ~c"secret".
  defp encrypted_rsa_pem do
    key = :public_key.generate_key({:rsa, 2048, 65_537})
    iv = :crypto.strong_rand_bytes(16)
    entry = :public_key.pem_entry_encode(:RSAPrivateKey, key, {{~c"AES-128-CBC", iv}, ~c"secret"})
    :public_key.pem_encode([entry])
  end

  setup do
    pem = encrypted_rsa_pem()
    # Sanity: it really is a single, encrypted RSA entry, so the failures
    # below are about the *encryption*, not about an empty or multi-entry
    # PEM. `pem_decode/1` returns one entry tagged :RSAPrivateKey even
    # though the body is ciphertext (the entry carries the cipher info).
    assert [{:RSAPrivateKey, _body, cipher_info}] = :public_key.pem_decode(pem)
    assert cipher_info != :not_encrypted
    assert String.contains?(pem, "ENCRYPTED")
    {:ok, pem: pem}
  end

  describe "jwk/1 on an encrypted PEM (no passphrase)" do
    test "raises the documented clear ArgumentError", %{pem: pem} do
      # `jwk/1` routes through `safe_from_pem/1`, which rescues JOSE's
      # failure on the un-decryptable entry and normalises it to the one
      # documented message. This is the GOOD shape: a deploy-time config
      # error surfaced clearly.
      assert_raise ArgumentError, ~r/did not contain exactly one parseable key/, fn ->
        Key.jwk(pem)
      end
    end
  end

  describe "kid/1 on an encrypted PEM (no passphrase)" do
    test "raises the same clear ArgumentError (it delegates to jwk/1)", %{pem: pem} do
      assert_raise ArgumentError, ~r/did not contain exactly one parseable key/, fn ->
        Key.kid(pem)
      end
    end
  end

  describe "public_pem/1 on an encrypted PEM (no passphrase)" do
    test "raises the documented clear ArgumentError", %{pem: pem} do
      assert_raise ArgumentError, ~r/invalid RSA private key PEM/, fn ->
        Key.public_pem(pem)
      end
    end

    test "does not expose the internal PEM decoder exception" do
      pem = encrypted_rsa_pem()

      err =
        try do
          Key.public_pem(pem)
          flunk("expected public_pem/1 to raise on an encrypted PEM")
        rescue
          e -> e
        end

      assert is_struct(err, ArgumentError)
      assert Exception.message(err) == "invalid RSA private key PEM"
    end
  end
end
