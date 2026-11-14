defmodule Attesto.PairwiseSubject do
  @moduledoc """
  Pairwise Subject Identifiers (OpenID Connect Core 1.0 §8.1).

  A pairwise `sub` is a different value for each sector of Relying Parties, so
  two clients in different sectors cannot correlate one End-User by comparing
  subject identifiers. This module holds the two pure rules: which sector a
  client belongs to, and how a `sub` is derived for it.

  ## Sector identifier

  §8.1 defines the sector identifier as the host component of the client's
  `sector_identifier_uri` when it registered one, and otherwise the host
  component of its registered `redirect_uri`, which then requires every
  registered redirect URI to share one host. This module implements the
  second form only: `sector_identifier/1` takes the registered redirect URIs
  and answers `{:error, :multiple_hosts}` when they span hosts. Fetching and
  validating a `sector_identifier_uri` document (§8.1) is not implemented, so a
  client whose redirect URIs span hosts cannot use pairwise identifiers.

  ## Derivation

  `derive/3` computes

      base64url(HMAC-SHA256(salt, len(sector) || sector || local_subject))

  where `len(sector)` is the sector identifier's byte length as a 32-bit
  integer. §8.1 allows any method that is deterministic, cannot be reversed by
  anyone but the provider, and gives different results per sector. The length
  prefix keeps two different `(sector, subject)` pairs from producing the same
  input. The value is stable for as long as the salt, the sector identifier
  and the local subject are: changing the salt, or moving a client to another
  redirect host, changes every `sub` that client sees.
  """

  @min_salt_bytes 32
  @subject_types ["public", "pairwise"]
  @sealed_claim "attesto.pairwise_subject"
  @seal_key_info "attesto.pairwise_subject.v1"
  @seal_nonce_bytes 32
  @seal_block_bytes 64
  @max_sealed_subject_bytes 65_535
  @zero_iv <<0::96>>
  @gcm_tag_bytes 16

  @doc false
  @spec sealed_claim() :: String.t()
  def sealed_claim, do: @sealed_claim

  @doc ~s(The subject types this module knows: `["public", "pairwise"]`.)
  @spec subject_types() :: [String.t()]
  def subject_types, do: @subject_types

  @doc "The minimum salt length `derive/3` accepts, in bytes."
  @spec min_salt_bytes() :: pos_integer()
  def min_salt_bytes, do: @min_salt_bytes

  @doc "Whether `salt` is usable: a binary of at least `min_salt_bytes/0` bytes."
  @spec valid_salt?(term()) :: boolean()
  def valid_salt?(salt), do: is_binary(salt) and byte_size(salt) >= @min_salt_bytes

  @doc """
  The sector identifier for a client with these registered redirect URIs: the
  host they all share, lowercased.

  Returns `{:error, :no_redirect_uris}` for an empty list,
  `{:error, :invalid_redirect_uri}` when one has no host, and
  `{:error, :multiple_hosts}` when they do not all share one host.
  """
  @spec sector_identifier([String.t()]) ::
          {:ok, String.t()} | {:error, :no_redirect_uris | :invalid_redirect_uri | :multiple_hosts}
  def sector_identifier([]), do: {:error, :no_redirect_uris}

  def sector_identifier(redirect_uris) when is_list(redirect_uris) do
    hosts = Enum.map(redirect_uris, &host/1)

    cond do
      Enum.any?(hosts, &is_nil/1) -> {:error, :invalid_redirect_uri}
      match?([_single], Enum.uniq(hosts)) -> {:ok, hd(hosts)}
      true -> {:error, :multiple_hosts}
    end
  end

  def sector_identifier(_redirect_uris), do: {:error, :no_redirect_uris}

  @doc """
  Derive the pairwise `sub` for `local_subject` in `sector_identifier`.

  Raises `ArgumentError` for a salt shorter than `min_salt_bytes/0` or an
  empty sector identifier or subject.
  """
  @spec derive(String.t(), String.t(), binary()) :: String.t()
  def derive(sector, subject, salt)
      when is_binary(sector) and sector != "" and is_binary(subject) and subject != "" and is_binary(salt) and
             byte_size(salt) >= @min_salt_bytes do
    derive_valid(sector, subject, salt)
  end

  def derive(_sector_identifier, _local_subject, _salt) do
    raise ArgumentError,
          "pairwise subject derivation needs a non-empty sector identifier and subject and a salt of at least " <>
            "#{@min_salt_bytes} bytes"
  end

  defp derive_valid(sector_identifier, local_subject, salt) do
    input = <<byte_size(sector_identifier)::32, sector_identifier::binary, local_subject::binary>>

    :hmac
    |> :crypto.mac(:sha256, salt, input)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Encrypt `local_subject` for recovery by the authorization server or a same-deployment
  resource server sharing `salt`.

  Pads the length-prefixed subject to a multiple of #{@seal_block_bytes} bytes
  and derives a single-use AES-256-GCM key per call from a fresh random 32-byte
  token nonce via HMAC-SHA256, with `pairwise_sub` as associated authenticated
  data. Two tokens therefore carry distinct ciphertexts that cannot be
  correlated, short subjects share the same ciphertext size, and the ciphertext
  is bound to its `sub`.
  """
  @spec seal_subject(String.t(), String.t(), binary()) :: String.t()
  def seal_subject(subject, pairwise_sub, salt) do
    if non_empty?(subject) and byte_size(subject) <= @max_sealed_subject_bytes and non_empty?(pairwise_sub) and
         valid_salt?(salt) do
      token_nonce = :crypto.strong_rand_bytes(@seal_nonce_bytes)
      key = per_token_seal_key(salt, token_nonce)
      plaintext = pad_subject(subject)

      {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, @zero_iv, plaintext, pairwise_sub, true)
      Base.url_encode64(token_nonce <> tag <> ciphertext, padding: false)
    else
      raise ArgumentError,
            "pairwise subject sealing needs non-empty subject (<= #{@max_sealed_subject_bytes} bytes), " <>
              "non-empty pairwise_sub, and a salt of at least #{@min_salt_bytes} bytes"
    end
  end

  defp non_empty?(value), do: is_binary(value) and value != ""

  @doc """
  Decrypt a sealed subject produced by `seal_subject/3`, authenticating against
  `pairwise_sub` and `salt`.
  """
  @spec unseal_subject(term(), term(), term()) :: {:ok, String.t()} | :error
  def unseal_subject(sealed, pairwise_sub, salt)
      when is_binary(sealed) and is_binary(pairwise_sub) and pairwise_sub != "" and is_binary(salt) and
             byte_size(salt) >= @min_salt_bytes do
    with {:ok, <<token_nonce::binary-size(@seal_nonce_bytes), tag::binary-size(@gcm_tag_bytes), ciphertext::binary>>}
         when byte_size(ciphertext) >= @seal_block_bytes and rem(byte_size(ciphertext), @seal_block_bytes) == 0 <-
           Base.url_decode64(sealed, padding: false),
         key = per_token_seal_key(salt, token_nonce),
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(:aes_256_gcm, key, @zero_iv, ciphertext, pairwise_sub, tag, false) do
      unpad_subject(plaintext)
    else
      _ -> :error
    end
  end

  def unseal_subject(_sealed, _pairwise_sub, _salt), do: :error

  defp per_token_seal_key(salt, token_nonce) do
    master = :crypto.mac(:hmac, :sha256, salt, @seal_key_info)
    :crypto.mac(:hmac, :sha256, master, token_nonce)
  end

  defp pad_subject(subject) do
    payload = <<byte_size(subject)::16, subject::binary>>
    rem_bytes = rem(byte_size(payload), @seal_block_bytes)
    pad_bytes = if rem_bytes == 0, do: 0, else: @seal_block_bytes - rem_bytes
    payload <> :binary.copy(<<0>>, pad_bytes)
  end

  defp unpad_subject(<<len::16, subject::binary-size(len), rest::binary>>) when len > 0 do
    expected = :binary.copy(<<0>>, byte_size(rest))
    if :crypto.hash_equals(rest, expected), do: {:ok, subject}, else: :error
  end

  defp unpad_subject(_plaintext), do: :error

  defp host(uri) when is_binary(uri) do
    with true <- Attesto.URI.https_identifier?(uri),
         {:ok, %URI{host: host}} when is_binary(host) and host != "" <- URI.new(uri),
         downcased = String.downcase(host),
         false <- Attesto.URI.loopback_host?(downcased) do
      downcased
    else
      _other -> nil
    end
  end

  defp host(_uri), do: nil
end
