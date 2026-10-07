defmodule Attesto.JWE do
  @moduledoc """
  Bounded compact JWE encryption for credential issuance and presentation.

  Supports ECDH-ES with a P-256 recipient key and A128GCM or A256GCM. Callers
  select the algorithms from authenticated protocol metadata and may narrow
  them with `:accepted_algs` and `:accepted_encs`. This module performs no
  network access or protocol-specific claim validation.

  Input and plaintext limits default to 1 MiB. `:max_compact_bytes` and
  `:max_plaintext_bytes` may explicitly override them. Protected headers are
  limited to 16 KiB. Compression, critical extensions, duplicate JSON members,
  noncanonical Base64URL, and invalid fixed-length GCM parameters are rejected
  before decryption.
  """

  alias Attesto.JWS

  @default_max_bytes 1_048_576
  @max_header_bytes 16_384
  @encs ~w(A128GCM A256GCM)
  @type key :: JOSE.JWK.t() | map()
  @type error :: :invalid_jwe | :invalid_key | :invalid_header | :invalid_options | :size_limit

  @doc """
  Encrypt bytes to a recipient using an authenticated protected header.

  The header must include `alg` and `enc`. JOSE generates a fresh ephemeral
  key; callers cannot supply `epk`. Private recipient keys are reduced to
  their public part before encryption.
  """
  @spec encrypt(key(), binary(), map(), keyword()) :: {:ok, binary()} | {:error, error()}
  def encrypt(recipient, plaintext, header, opts \\ [])

  def encrypt(recipient, plaintext, header, opts) when is_binary(plaintext) and is_map(header) and is_list(opts) do
    with {:ok, limits} <- options(opts),
         :ok <- within_limit(plaintext, limits.plaintext),
         :ok <- validate_header(header, opts),
         false <- Map.has_key?(header, "epk"),
         {:ok, key} <- recipient_key(recipient, :encrypt),
         :ok <- within_limit(JWS.encode64(JSON.encode!(header)), @max_header_bytes),
         ephemeral = JOSE.JWK.generate_key({:ec, "P-256"}),
         {_modules, compact} <- JOSE.JWE.block_encrypt({key, ephemeral}, plaintext, header) |> JOSE.JWE.compact(),
         :ok <- within_limit(compact, limits.compact),
         {:ok, _segments} <- split_compact(compact) do
      {:ok, compact}
    else
      true -> {:error, :invalid_header}
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_jwe}
    end
  rescue
    _error -> {:error, :invalid_jwe}
  catch
    _kind, _reason -> {:error, :invalid_jwe}
  end

  def encrypt(_recipient, _plaintext, _header, _opts), do: {:error, :invalid_jwe}

  @doc """
  Authenticate and decrypt a compact JWE, returning its protected header.

  The recipient must include private key material. All compact and protected
  header checks run before JOSE processes the ciphertext.
  """
  @spec decrypt(key(), binary(), keyword()) :: {:ok, binary(), map()} | {:error, error()}
  def decrypt(recipient, compact, opts \\ [])

  def decrypt(recipient, compact, opts) when is_binary(compact) and is_list(opts) do
    with {:ok, limits} <- options(opts),
         :ok <- within_limit(compact, limits.compact),
         {:ok, segments} <- split_compact(compact),
         {:ok, header} <- decode_header(segments.protected),
         :ok <- validate_header(header, opts),
         :ok <- validate_ephemeral(header),
         :ok <- validate_segments(segments, limits.plaintext),
         {:ok, key} <- recipient_key(recipient, :decrypt),
         {:ok, plaintext} <- decrypt_bytes(key, compact),
         :ok <- within_limit(plaintext, limits.plaintext) do
      {:ok, plaintext, header}
    else
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_jwe}
    end
  rescue
    _error -> {:error, :invalid_jwe}
  catch
    _kind, _reason -> {:error, :invalid_jwe}
  end

  def decrypt(_recipient, _compact, _opts), do: {:error, :invalid_jwe}

  defp decrypt_bytes(key, compact) do
    case JOSE.JWE.block_decrypt(key, compact) do
      {plaintext, %JOSE.JWE{}} when is_binary(plaintext) -> {:ok, plaintext}
      _other -> {:error, :invalid_jwe}
    end
  end

  defp options(opts) do
    compact = Keyword.get(opts, :max_compact_bytes, @default_max_bytes)
    plaintext = Keyword.get(opts, :max_plaintext_bytes, @default_max_bytes)

    if Keyword.keyword?(opts) and is_integer(compact) and compact > 0 and
         is_integer(plaintext) and plaintext > 0 and valid_alg_options?(opts) do
      {:ok, %{compact: compact, plaintext: plaintext}}
    else
      {:error, :invalid_options}
    end
  end

  defp valid_alg_options?(opts) do
    algs = Keyword.get(opts, :accepted_algs, ["ECDH-ES"])
    encs = Keyword.get(opts, :accepted_encs, @encs)

    is_list(algs) and algs != [] and Enum.all?(algs, &(&1 == "ECDH-ES")) and
      is_list(encs) and encs != [] and Enum.all?(encs, &(&1 in @encs))
  end

  defp within_limit(bytes, maximum) when byte_size(bytes) <= maximum, do: :ok
  defp within_limit(_bytes, _maximum), do: {:error, :size_limit}

  defp validate_header(%{"alg" => "ECDH-ES", "enc" => enc} = header, opts) do
    accepted_encs = Keyword.get(opts, :accepted_encs, @encs)

    with true <- enc in @encs and enc in accepted_encs,
         true <- Enum.all?(Map.keys(header), &is_binary/1),
         false <- Map.has_key?(header, "zip"),
         :ok <- JWS.reject_unsupported_crit(header),
         :ok <- party_info(header, "apu"),
         :ok <- party_info(header, "apv") do
      :ok
    else
      _other -> {:error, :invalid_header}
    end
  end

  defp validate_header(_header, _opts), do: {:error, :invalid_header}

  defp party_info(header, field) do
    case Map.fetch(header, field) do
      :error ->
        :ok

      {:ok, encoded} when is_binary(encoded) ->
        case JWS.decode64(encoded, max_encoded_bytes: @max_header_bytes) do
          {:ok, _bytes} -> :ok
          _other -> {:error, :invalid_header}
        end

      _other ->
        {:error, :invalid_header}
    end
  end

  defp recipient_key(%JOSE.JWK{} = key, operation) do
    {_modules, key_map} = JOSE.JWK.to_map(key)
    recipient_key(key_map, operation)
  end

  defp recipient_key(%{} = key, operation) do
    with :ok <- valid_p256_key(key),
         true <- Map.get(key, "use") in [nil, "enc"],
         true <- Map.get(key, "alg") in [nil, "ECDH-ES"],
         :ok <- key_operations(key, operation),
         :ok <- private_key(key, operation) do
      jose_key = JOSE.JWK.from_map(key)
      {:ok, if(operation == :encrypt, do: JOSE.JWK.to_public(jose_key), else: jose_key)}
    else
      _other -> {:error, :invalid_key}
    end
  end

  defp recipient_key(_key, _operation), do: {:error, :invalid_key}

  defp valid_p256_key(%{"kty" => "EC", "crv" => "P-256", "x" => x, "y" => y}) do
    with {:ok, x_bytes} when byte_size(x_bytes) == 32 <- JWS.decode64(x, max_encoded_bytes: 43),
         {:ok, y_bytes} when byte_size(y_bytes) == 32 <- JWS.decode64(y, max_encoded_bytes: 43) do
      :ok
    else
      _other -> {:error, :invalid_key}
    end
  end

  defp valid_p256_key(_key), do: {:error, :invalid_key}

  defp key_operations(key, operation) do
    case Map.fetch(key, "key_ops") do
      :error ->
        :ok

      {:ok, operations} when is_list(operations) and operations != [] ->
        permitted = [Atom.to_string(operation), "deriveKey", "deriveBits"]

        if Enum.all?(operations, &is_binary/1) and Enum.any?(operations, &(&1 in permitted)),
          do: :ok,
          else: {:error, :invalid_key}

      _other ->
        {:error, :invalid_key}
    end
  end

  defp private_key(_key, :encrypt), do: :ok

  defp private_key(key, :decrypt) do
    case JWS.decode64(Map.get(key, "d"), max_encoded_bytes: 43) do
      {:ok, bytes} when byte_size(bytes) == 32 -> :ok
      _other -> {:error, :invalid_key}
    end
  end

  defp split_compact(compact) do
    with [protected, rest] <- :binary.split(compact, "."),
         [encrypted_key, rest] <- :binary.split(rest, "."),
         [iv, rest] <- :binary.split(rest, "."),
         [ciphertext, tag] <- :binary.split(rest, "."),
         :nomatch <- :binary.match(tag, "."),
         true <- protected != "" and byte_size(protected) <= @max_header_bytes do
      {:ok, %{protected: protected, encrypted_key: encrypted_key, iv: iv, ciphertext: ciphertext, tag: tag}}
    else
      _other -> {:error, :invalid_jwe}
    end
  end

  defp decode_header(encoded) do
    case JWS.decode64(encoded, max_encoded_bytes: @max_header_bytes) do
      {:ok, bytes} -> strict_json_map(bytes)
      _other -> {:error, :invalid_header}
    end
  end

  defp strict_json_map(bytes) do
    decoders = [
      object_start: fn _acc -> %{} end,
      object_push: fn key, value, object ->
        if Map.has_key?(object, key), do: throw(:duplicate_json_member), else: Map.put(object, key, value)
      end,
      object_finish: fn object, acc -> {object, acc} end
    ]

    case JSON.decode(bytes, nil, decoders) do
      {%{} = header, nil, ""} -> {:ok, header}
      _other -> {:error, :invalid_header}
    end
  rescue
    _error -> {:error, :invalid_header}
  catch
    :duplicate_json_member -> {:error, :invalid_header}
  end

  defp validate_ephemeral(%{"epk" => %{} = epk}) do
    if valid_p256_key(epk) == :ok and not Map.has_key?(epk, "d"),
      do: :ok,
      else: {:error, :invalid_header}
  end

  defp validate_ephemeral(_header), do: {:error, :invalid_header}

  defp validate_segments(%{encrypted_key: "", iv: iv, ciphertext: ciphertext, tag: tag}, max_plaintext)
       when byte_size(iv) == 16 and byte_size(tag) == 22 do
    with {:ok, iv_bytes} when byte_size(iv_bytes) == 12 <- JWS.decode64(iv),
         {:ok, tag_bytes} when byte_size(tag_bytes) == 16 <- JWS.decode64(tag),
         {:ok, cipher_bytes} when byte_size(cipher_bytes) <= max_plaintext <-
           JWS.decode64(ciphertext, max_encoded_bytes: div(max_plaintext * 4 + 2, 3)) do
      :ok
    else
      _other -> {:error, :invalid_jwe}
    end
  end

  defp validate_segments(_segments, _max_plaintext), do: {:error, :invalid_jwe}
end
