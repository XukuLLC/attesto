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

  defp host(uri) when is_binary(uri) do
    case URI.new(uri) do
      {:ok, %URI{host: host}} when is_binary(host) and host != "" -> String.downcase(host)
      _ -> nil
    end
  end

  defp host(_uri), do: nil
end
