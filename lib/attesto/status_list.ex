defmodule Attesto.StatusList do
  @moduledoc """
  IETF Token Status List construction and verification.

  Status values are packed into a compact bit array, compressed with zlib,
  and carried in a signed `statuslist+jwt`. Fetching is deliberately supplied
  by the host through resolver functions, so this module has no HTTP or Plug
  dependency.
  """

  import Bitwise

  alias Attesto.{JWS, MapParams, NumericDate, SigningAlg}

  @header_typ "statuslist+jwt"
  @valid_bits [1, 2, 4, 8]

  @type bits :: 1 | 2 | 4 | 8
  @type verified :: %{
          bits: bits(),
          statuses_binary: binary(),
          sub: String.t(),
          claims: map()
        }

  @doc """
  Pack status values into bytes, placing the first entry in each byte's least
  significant field.
  """
  @spec pack([non_neg_integer()], bits()) :: binary()
  def pack(statuses, bits) when is_list(statuses) do
    validate_bits!(bits)
    entries_per_byte = div(8, bits)

    statuses
    |> Enum.chunk_every(entries_per_byte)
    |> Enum.map(&pack_byte(&1, bits))
    |> :erlang.list_to_binary()
  end

  def pack(_statuses, bits) do
    validate_bits!(bits)
    raise ArgumentError, "statuses must be a list of non-negative integers"
  end

  @doc """
  Build an unsigned `status_list` claim.

  `:bits` defaults to `1`.
  """
  @spec build([non_neg_integer()], keyword()) :: %{required(String.t()) => term()}
  def build(statuses, opts \\ []) do
    opts = MapParams.ensure_keyword!(opts)
    bits = Keyword.get(opts, :bits, 1)

    encoded =
      statuses
      |> pack(bits)
      |> :zlib.compress()
      |> JWS.encode64()

    %{"bits" => bits, "lst" => encoded}
  end

  @doc "Sign a caller-supplied Status List Token claim set with the required type."
  @spec sign(module(), map(), keyword()) :: String.t()
  def sign(keystore, claims, opts \\ []) when is_atom(keystore) and is_map(claims) do
    opts = MapParams.ensure_keyword!(opts)
    claims = MapParams.string_keyed_map(claims)

    JWS.sign_current(keystore, claims, Keyword.put(opts, :typ, @header_typ))
  end

  @doc """
  Build and sign a Status List Token for `uri`.

  Options are `:bits` (default `1`), `:exp`, `:ttl`, and `:now`.
  """
  @spec issue(module(), String.t(), [non_neg_integer()], keyword()) :: String.t()
  def issue(keystore, uri, statuses, opts \\ []) when is_atom(keystore) do
    opts = MapParams.ensure_keyword!(opts)
    uri = MapParams.required_string!(uri, :uri)

    claims =
      %{
        "status_list" => build(statuses, opts),
        "sub" => uri,
        "iat" => NumericDate.now(opts)
      }
      |> MapParams.put_optional("exp", Keyword.get(opts, :exp))
      |> MapParams.put_optional("ttl", Keyword.get(opts, :ttl))

    sign(keystore, claims, opts)
  end

  @doc """
  Verify and decode a Status List Token.

  `:accepted_algs` limits the trusted signing algorithms. By default all
  asymmetric algorithms supported by Attesto are accepted.
  """
  @spec verify(String.t(), map() | [map()], keyword()) ::
          {:ok, verified()} | {:error, atom()}
  def verify(token, jwks, opts \\ [])

  def verify(token, jwks, opts) when is_binary(token) do
    opts = MapParams.ensure_keyword!(opts)

    with {:ok, header} <- peek_header(token),
         :ok <- check_typ(header),
         :ok <- check_crit(header),
         {:ok, alg} <- accepted_alg(header, opts),
         {:ok, claims} <- verify_signature(token, header, alg, jwks) do
      decode_status_list(claims)
    end
  end

  def verify(_token, _jwks, _opts), do: {:error, :invalid_signature}

  @doc "Read the status value at `idx` from a packed status array."
  @spec status_at(binary(), bits(), non_neg_integer()) :: non_neg_integer()
  def status_at(packed, bits, idx) when is_binary(packed) and is_integer(idx) and idx >= 0 do
    validate_bits!(bits)
    entries_per_byte = div(8, bits)

    if idx >= byte_size(packed) * entries_per_byte do
      raise ArgumentError, "status index is out of range"
    end

    byte = :binary.at(packed, div(idx, entries_per_byte))
    offset = rem(idx, entries_per_byte) * bits
    byte >>> offset &&& (1 <<< bits) - 1
  end

  def status_at(_packed, bits, _idx) do
    validate_bits!(bits)
    raise ArgumentError, "status index must be a non-negative integer within the packed array"
  end

  @doc "Build the `status` claim carried by a token that references a status list."
  @spec reference(String.t(), non_neg_integer()) :: %{required(String.t()) => term()}
  def reference(uri, idx) when is_integer(idx) and idx >= 0 do
    uri = MapParams.required_string!(uri, :uri)
    %{"status_list" => %{"idx" => idx, "uri" => uri}}
  end

  def reference(uri, _idx) do
    _ = MapParams.required_string!(uri, :uri)
    raise ArgumentError, ":idx must be a non-negative integer"
  end

  @doc """
  Resolve a referenced token's status without performing HTTP.

  `resolver` fetches the Status List Token for a URI and returns
  `{:ok, token}`. The third argument may be trusted JWKS directly or a
  function that resolves the trusted JWKS for that URI.
  """
  @spec resolve(map(), (String.t() -> {:ok, String.t()} | {:error, term()}), term(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def resolve(status_claim, resolver, jwks_or_resolver, opts \\ [])

  def resolve(status_claim, resolver, jwks_or_resolver, opts) when is_map(status_claim) and is_function(resolver, 1) do
    opts = MapParams.ensure_keyword!(opts)

    with {:ok, uri, idx} <- status_reference(status_claim),
         {:ok, token} <- fetch_token(resolver, uri),
         {:ok, jwks} <- trusted_jwks(jwks_or_resolver, uri),
         {:ok, verified} <- verify(token, jwks, opts),
         :ok <- matching_subject(verified.sub, uri) do
      read_status(verified.statuses_binary, verified.bits, idx)
    end
  end

  def resolve(_status_claim, _resolver, _jwks_or_resolver, _opts), do: {:error, :invalid_status_reference}

  defp pack_byte(statuses, bits) do
    max_status = 1 <<< bits

    statuses
    |> Enum.with_index()
    |> Enum.reduce(0, fn {status, index}, byte ->
      validate_status!(status, max_status)
      byte ||| status <<< (index * bits)
    end)
  end

  defp validate_status!(status, max_status) when is_integer(status) and status >= 0 and status < max_status, do: :ok

  defp validate_status!(status, max_status) do
    raise ArgumentError,
          "status must be a non-negative integer below #{max_status}; got #{inspect(status)}"
  end

  defp validate_bits!(bits) when bits in @valid_bits, do: :ok

  defp validate_bits!(bits) do
    raise ArgumentError, ":bits must be one of 1, 2, 4, or 8; got #{inspect(bits)}"
  end

  defp peek_header(token) do
    case JWS.peek_json(token, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :invalid_signature}
    end
  end

  defp check_typ(%{"typ" => @header_typ}), do: :ok
  defp check_typ(_header), do: {:error, :invalid_typ}

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :invalid_signature}
    end
  end

  defp accepted_alg(header, opts) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    case Map.get(header, "alg") do
      alg when is_binary(alg) and alg != "none" ->
        if is_list(accepted) and (accepted == [] or alg in accepted),
          do: {:ok, alg},
          else: {:error, :unsupported_alg}

      _other ->
        {:error, :unsupported_alg}
    end
  end

  defp verify_signature(token, header, alg, jwks) do
    candidates =
      JWS.verification_candidates(jwks,
        accepted_algs: [alg],
        kid: Map.get(header, "kid"),
        malformed_key: :skip
      )

    JWS.verify_strict(token, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :continue,
      malformed_error: :invalid_signature,
      claims_map?: true
    )
  end

  defp decode_status_list(%{"status_list" => %{"bits" => bits, "lst" => encoded}, "sub" => sub} = claims)
       when bits in @valid_bits and is_binary(encoded) and is_binary(sub) and sub != "" do
    with {:ok, compressed} <- JWS.decode64(encoded),
         {:ok, packed} <- inflate(compressed) do
      {:ok, %{bits: bits, statuses_binary: packed, sub: sub, claims: claims}}
    else
      {:error, _reason} -> {:error, :invalid_status_list}
    end
  end

  defp decode_status_list(_claims), do: {:error, :invalid_status_list}

  # Cap on the INFLATED status bitstring. The list is signed by the status
  # issuer, so a compromised/malicious issuer can sign a zlib bomb (~1032:1) that
  # passes verification and then detonates here; a plain `:zlib.uncompress/1`
  # would expand a tiny token to gigabytes and OOM the node on every status
  # check. 16 MiB is 128M single-bit statuses - far beyond any real list.
  @max_inflated_bytes 16 * 1024 * 1024

  defp inflate(compressed) do
    z = :zlib.open()

    try do
      :zlib.inflateInit(z)
      bounded_inflate(z, :zlib.safeInflate(z, compressed), [], 0)
    rescue
      _error -> {:error, :invalid_compression}
    catch
      _kind, _reason -> {:error, :invalid_compression}
    after
      :zlib.close(z)
    end
  end

  # Stream the inflate and abort the moment output exceeds the cap, so memory
  # stays O(cap) regardless of the declared or actual expanded size.
  defp bounded_inflate(z, {:continue, output}, acc, total) do
    total = total + IO.iodata_length(output)

    if total > @max_inflated_bytes do
      {:error, :status_list_too_large}
    else
      bounded_inflate(z, :zlib.safeInflate(z, []), [acc, output], total)
    end
  end

  defp bounded_inflate(_z, {:finished, output}, acc, total) do
    if total + IO.iodata_length(output) > @max_inflated_bytes do
      {:error, :status_list_too_large}
    else
      {:ok, IO.iodata_to_binary([acc, output])}
    end
  end

  defp status_reference(status_claim) do
    with %{} = status_list <- MapParams.fetch(status_claim, :status_list),
         idx when is_integer(idx) and idx >= 0 <- MapParams.fetch(status_list, :idx),
         uri when is_binary(uri) and uri != "" <- MapParams.fetch(status_list, :uri) do
      {:ok, uri, idx}
    else
      _other -> {:error, :invalid_status_reference}
    end
  end

  defp fetch_token(resolver, uri) do
    case resolver.(uri) do
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _token} -> {:error, :invalid_status_list_token}
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_status_list_token}
    end
  end

  defp trusted_jwks(resolver, uri) when is_function(resolver, 1) do
    case resolver.(uri) do
      {:ok, jwks} when is_map(jwks) or is_list(jwks) -> {:ok, jwks}
      {:error, _reason} = error -> error
      jwks when is_map(jwks) or is_list(jwks) -> {:ok, jwks}
      _other -> {:error, :invalid_jwks}
    end
  end

  defp trusted_jwks(jwks, _uri) when is_map(jwks) or is_list(jwks), do: {:ok, jwks}
  defp trusted_jwks(_jwks, _uri), do: {:error, :invalid_jwks}

  defp matching_subject(uri, uri), do: :ok
  defp matching_subject(_subject, _uri), do: {:error, :status_list_uri_mismatch}

  defp read_status(packed, bits, idx) do
    {:ok, status_at(packed, bits, idx)}
  rescue
    ArgumentError -> {:error, :status_index_out_of_range}
  end
end
