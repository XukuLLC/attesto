defmodule Attesto.StatusList do
  @moduledoc """
  IETF Token Status List (`draft-ietf-oauth-status-list-21`) construction and
  verification.

  Status values are packed into a compact bit array, compressed with zlib,
  and carried in a signed JWT or CWT. `fetch/3` provides a bounded,
  SSRF-screened default resolver using the optional Mint dependency. Hosts
  may also supply their own resolver functions.
  """

  import Bitwise

  alias Attesto.{Claims, JWS, MapParams, NumericDate, SigningAlg, X509}
  alias Attesto.StatusList.Cache

  @header_typ "statuslist+jwt"
  @accept_status_list_jwt "application/statuslist+jwt"
  @accept_status_list_cwt "application/statuslist+cwt"
  @accept_identifier_list_cwt "application/identifierlist+cwt"
  @valid_bits [1, 2, 4, 8]
  @expiry_leeway_seconds NumericDate.default_clock_skew_seconds()
  @max_status_list_token_bytes 1_048_576

  @doc "Maximum accepted wire size in bytes of a compact `statuslist+jwt` or CWT status list."
  @spec max_status_list_token_bytes() :: pos_integer()
  def max_status_list_token_bytes, do: @max_status_list_token_bytes

  @doc """
  Fetch a status or identifier list over HTTPS. DNS and the pinned connection
  share a five-second deadline; redirects are refused, the response media type
  must match `accept`, and the body is limited to 1 MiB. No credentials or
  cookies are sent. Requires the optional `:mint` dependency.

  Options: `:timeout` in milliseconds, `:resolver` for DNS, and
  `:allow_loopback` for local development (default `false`).
  """
  @spec fetch(String.t(), String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def fetch(uri, accept, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5_000)

    if is_integer(timeout) and timeout > 0 and
         accept in [@accept_status_list_jwt, @accept_status_list_cwt, @accept_identifier_list_cwt] do
      deadline = System.monotonic_time(:millisecond) + timeout
      task = Task.async(fn -> safe_fetch(uri, accept, deadline, opts) end)

      case Task.yield(task, timeout + 50) || Task.shutdown(task, :brutal_kill) do
        {:ok, result} -> result
        _ -> {:error, :status_list_fetch_timeout}
      end
    else
      {:error, :invalid_status_list_fetch_options}
    end
  end

  if Code.ensure_loaded?(Mint.HTTP) do
    defp safe_fetch(uri, accept, deadline, opts) do
      with {:ok, target} <- Attesto.OutboundTarget.screen(uri, Keyword.take(opts, [:resolver, :allow_loopback])),
           {:ok, response} <- pinned_status_request(target, accept, deadline) do
        status_list_response(response, accept)
      else
        {:error, {:maybe_sent, :too_large}} -> {:error, :too_large}
        error -> error
      end
    rescue
      _ -> {:error, :status_list_fetch_failed}
    catch
      _, _ -> {:error, :status_list_fetch_failed}
    end

    defp pinned_status_request(target, accept, deadline) do
      Attesto.PinnedHTTP.request_inline(
        target,
        method: :get,
        headers: [{"accept", accept}],
        deadline: deadline,
        body_limit: @max_status_list_token_bytes
      )
    end

    defp status_list_response(%{status: 200, headers: headers, body: body}, accept) do
      types = for {name, value} <- headers, String.downcase(name) == "content-type", do: value

      case types do
        [type] ->
          if type |> String.split(";", parts: 2) |> hd() |> String.trim() |> String.downcase() == accept,
            do: {:ok, body},
            else: {:error, :invalid_status_list_content_type}

        _ ->
          {:error, :invalid_status_list_content_type}
      end
    end

    defp status_list_response(%{status: status}, _accept), do: {:error, {:http_status, status}}
  else
    defp safe_fetch(_uri, _accept, _deadline, _opts), do: {:error, :missing_http_dependency}
  end

  @doc """
  Resolve credential verification's `:resolve_status` option. Omission selects
  the screened default fetcher. Explicit `false` is reserved for offline
  inspection; applications making acceptance decisions must enforce status.
  """
  @spec resolver(keyword()) :: false | function()
  def resolver(opts) do
    case Keyword.fetch(opts, :resolve_status) do
      :error -> &__MODULE__.fetch/2
      {:ok, false} -> false
      {:ok, fun} when is_function(fun, 1) or is_function(fun, 2) -> fun
      _ -> raise ArgumentError, ":resolve_status must be false or a 1-arity or 2-arity function"
    end
  end

  @type bits :: 1 | 2 | 4 | 8
  @type verified :: %{
          bits: bits(),
          statuses_binary: binary(),
          sub: String.t(),
          claims: map()
        }
  @type verified_identifier_list :: %{
          identifiers: MapSet.t(binary()),
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
  @spec verify(String.t(), map() | [map()] | nil, keyword()) ::
          {:ok, verified()} | {:error, atom()}
  def verify(token, jwks, opts \\ [])

  def verify(token, jwks, opts) when is_binary(token) do
    opts = MapParams.ensure_keyword!(opts)

    with {:ok, header} <-
           JWS.protected_header(token,
             error: :invalid_signature,
             crit_error: :invalid_signature,
             max_compact_bytes: @max_status_list_token_bytes
           ),
         :ok <- check_typ(header),
         {:ok, alg} <- accepted_alg(header, opts),
         {:ok, verification_jwks} <- jwt_verification_keys(header, jwks, opts),
         {:ok, claims} <- verify_signature(token, header, alg, verification_jwks),
         :ok <- check_expiry(claims, opts) do
      decode_status_list(claims)
    end
  end

  def verify(_token, _jwks, _opts), do: {:error, :invalid_signature}

  defp jwt_verification_keys(header, jwks, opts) do
    cond do
      is_binary(Keyword.get(opts, :reference_certificate)) ->
        jwt_reference_certificate_keys(header, Keyword.fetch!(opts, :reference_certificate))

      Keyword.has_key?(opts, :trusted_certificates) ->
        trust_opts = opts |> Keyword.put_new(:haip, true) |> Keyword.put(:purpose, :generic)

        with {:ok, chain} <- X509.decode_x5c(Map.get(header, "x5c")),
             {:ok, verified} <- X509.verify(chain, trust_opts) do
          {:ok, verified.public_key}
        end

      true ->
        {:ok, jwks}
    end
  end

  defp jwt_reference_certificate_keys(header, ref_cert) do
    chain_result =
      case Map.get(header, "x5c") do
        nil -> {:ok, [ref_cert]}
        raw_x5c -> X509.decode_x5c(raw_x5c)
      end

    with {:ok, chain} <- chain_result,
         {:ok, verified} <-
           X509.verify(chain,
             trusted_certificates: [ref_cert],
             purpose: :generic,
             haip: false
           ) do
      {:ok, verified.public_key}
    end
  end

  # draft-ietf-oauth-status-list §11.5: a relying party MUST NOT trust an
  # expired Status List Token. `exp` is optional in the spec, so a token without
  # one does not expire; when present it is honored with a small clock-skew
  # leeway. A non-integer `exp` is malformed. Pass `now:`/`leeway:` to override.
  defp check_expiry(claims, opts) do
    now = NumericDate.now(opts, default: :system, invalid_override: :fallback)
    leeway = Keyword.get(opts, :leeway, @expiry_leeway_seconds)

    with :ok <- check_jwt_exp(Map.fetch(claims, "exp"), now, leeway),
         :ok <- check_jwt_iat(Map.fetch(claims, "iat"), now, leeway, Keyword.get(opts, :require_iat, false)) do
      check_optional_ttl(Map.fetch(claims, "ttl"))
    end
  end

  defp check_jwt_exp(:error, _now, _leeway), do: :ok

  defp check_jwt_exp({:ok, exp}, now, leeway) when is_integer(exp) do
    if NumericDate.not_expired?(exp, now, leeway: leeway), do: :ok, else: {:error, :expired}
  end

  defp check_jwt_exp(_invalid, _now, _leeway), do: {:error, :invalid_status_list}

  defp check_jwt_iat(:error, _now, _leeway, false), do: :ok
  defp check_jwt_iat(:error, _now, _leeway, true), do: {:error, :invalid_status_list}

  defp check_jwt_iat({:ok, iat}, now, leeway, _require_iat?) when is_integer(iat) do
    if NumericDate.not_before_reached?(iat, now, skew: leeway), do: :ok, else: {:error, :invalid_status_list}
  end

  defp check_jwt_iat(_invalid, _now, _leeway, _require_iat?), do: {:error, :invalid_status_list}

  defp check_optional_ttl(:error), do: :ok
  defp check_optional_ttl({:ok, ttl}) when is_integer(ttl) and ttl >= 0, do: :ok
  defp check_optional_ttl(_invalid), do: {:error, :invalid_status_list}

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

  A Status List Token without an `exp` claim is treated as non-expiring by
  `verify/3` (matching `draft-ietf-oauth-status-list` §11.5). The host's
  `resolver` must therefore bound how long a fetched token is cached: honor the
  verified token's `ttl` claim when present, and enforce a fixed maximum cache
  age when `ttl` is absent.
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

  defp check_typ(header) do
    if Claims.typ_matches?(Map.get(header, "typ"), [@header_typ], normalization: :application_subtype),
      do: :ok,
      else: {:error, :invalid_typ}
  end

  defp accepted_alg(header, opts) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    case Map.get(header, "alg") do
      alg when is_binary(alg) and alg != "none" ->
        if SigningAlg.valid_verification_algorithms?(accepted) and alg in accepted,
          do: {:ok, alg},
          else: {:error, :unsupported_alg}

      _other ->
        {:error, :unsupported_alg}
    end
  end

  defp verify_signature(token, header, alg, jwks) do
    JWS.verify_trusted(token, header, jwks,
      accepted_algs: [alg],
      malformed_key: :skip,
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

  # `safeInflate/2` also answers `:finished` when the input simply ran out, so
  # a ZLIB stream cut short would be read as a complete, shorter list.
  # `inflateEnd/1` raises unless the end of the stream was reached (and its
  # Adler-32 verified), and `inflate/1` turns that into `:invalid_compression`.
  # Bytes after the end of a complete stream are not part of the list and are
  # ignored.
  defp bounded_inflate(z, {:finished, output}, acc, total) do
    if total + IO.iodata_length(output) > @max_inflated_bytes do
      {:error, :status_list_too_large}
    else
      :ok = :zlib.inflateEnd(z)
      {:ok, IO.iodata_to_binary([acc, output])}
    end
  end

  @doc """
  Verify a credential's revocation status against a fetched Status List Token
  (`statuslist+jwt` or `statuslist+cwt`) or ISO 18013-5 Identifier List Token
  (`identifierlist+cwt`).

  Returns `:ok` when the credential has no status reference (`nil`) or when the
  referenced status entry is valid (`0` in a status list, or absent from an
  identifier list). Returns `{:error, :credential_revoked}` when the status list
  entry is `1` or the credential identifier is present in the identifier
  list. Status `2` returns `:credential_suspended`; other nonzero values return
  `{:credential_status, value}`. Fails closed with `{:error, reason}` when the reference or list token
  cannot be fetched or verified.

  `resolver` is a 1-arity function of the URI or a 2-arity function of the URI
  and the accepted media type. Either returns `{:ok, binary()}` or
  `{:error, term()}`. `:status_trusted_certificates` restricts list signers to the
  supplied DER anchors without changing credential verification trust.
  """
  @spec check_status(map() | nil, function(), term(), keyword()) :: :ok | {:error, term()}
  def check_status(status_claim, resolver, trusted, opts \\ [])

  def check_status(nil, _resolver, _trusted, _opts), do: :ok

  def check_status(status_claim, resolver, trusted, opts)
      when is_map(status_claim) and (is_function(resolver, 1) or is_function(resolver, 2)) do
    opts = MapParams.ensure_keyword!(opts)

    opts =
      case Keyword.fetch(opts, :status_trusted_certificates) do
        {:ok, anchors} -> Keyword.put(opts, :trusted_certificates, anchors)
        :error -> opts
      end

    case parse_revocation_reference(status_claim) do
      {:ok, :status_list, uri, idx, ref_cert} ->
        check_status_list_reference(uri, idx, ref_cert, resolver, trusted, opts)

      {:ok, :identifier_list, uri, id_bytes, ref_cert} ->
        check_identifier_list_reference(uri, id_bytes, ref_cert, resolver, trusted, opts)

      {:error, _reason} = error ->
        error
    end
  end

  def check_status(_status_claim, _resolver, _trusted, _opts), do: {:error, :invalid_status_reference}

  defp check_status_list_reference(uri, idx, ref_cert, resolver, trusted, opts) do
    format = Keyword.get(opts, :format, :jwt)
    media_type = if format == :cwt, do: @accept_status_list_cwt, else: @accept_status_list_jwt
    verify_opts = opts |> maybe_put_reference_cert(ref_cert) |> Keyword.put_new(:require_iat, true)

    verify = fn token ->
      with {:ok, resolved_trust} <- resolve_trust(trusted, uri, verify_opts),
           {:ok, verified} <- verify_status_list_by_format(format, token, resolved_trust, verify_opts),
           :ok <- matching_subject(verified.sub, uri),
           do: {:ok, verified}
    end

    with {:ok, verified} <- verified_list(uri, media_type, resolver, verify_opts, verify),
         {:ok, status} <- read_status(verified.statuses_binary, verified.bits, idx) do
      status_result(status)
    else
      {:error, reason} -> {:error, normalize_status_error(reason)}
    end
  end

  if Code.ensure_loaded?(CBOR) do
    defp check_identifier_list_reference(uri, id_bytes, ref_cert, resolver, trusted, opts) do
      verify_opts = maybe_put_reference_cert(opts, ref_cert)

      verify = fn token ->
        with {:ok, resolved_trust} <- resolve_trust(trusted, uri, verify_opts),
             {:ok, verified} <- verify_identifier_list_cwt(token, resolved_trust, verify_opts),
             :ok <- matching_subject(verified.sub, uri),
             do: {:ok, verified}
      end

      case verified_list(uri, @accept_identifier_list_cwt, resolver, verify_opts, verify) do
        {:ok, verified} ->
          if MapSet.member?(verified.identifiers, id_bytes),
            do: {:error, :credential_revoked},
            else: :ok

        {:error, reason} ->
          {:error, normalize_status_error(reason)}
      end
    end
  else
    defp check_identifier_list_reference(_uri, _id, _cert, _resolver, _trust, _opts),
      do: {:error, :missing_cbor_dependency}
  end

  defp status_result(0), do: :ok
  defp status_result(1), do: {:error, :credential_revoked}
  defp status_result(2), do: {:error, :credential_suspended}
  defp status_result(value), do: {:error, {:credential_status, value}}

  defp verified_list(uri, media_type, resolver, opts, verify) do
    use_cache = Keyword.get(opts, :cache_status, resolver == (&__MODULE__.fetch/2))
    key = {uri, media_type}
    now = NumericDate.now(opts, default: :system, invalid_override: :fallback)

    cached = if use_cache, do: Cache.get(key, now), else: :miss

    case cached do
      {:ok, token} ->
        case verify.(token) do
          {:ok, _} = result ->
            result

          {:error, _} ->
            # A failure under this caller's trust does not invalidate a list
            # already verified for another caller. Replace only on success.
            fetch_verified_list(key, resolver, now, use_cache, verify)
        end

      _ ->
        fetch_verified_list(key, resolver, now, use_cache, verify)
    end
  end

  defp fetch_verified_list({uri, media_type} = key, resolver, now, use_cache, verify) do
    with {:ok, token} <- fetch_token(resolver, uri, media_type),
         {:ok, verified} <- verify.(token) do
      if use_cache, do: Cache.put(key, token, verified.claims, now)
      {:ok, verified}
    end
  end

  defp verify_status_list_by_format(:cwt, token, trusted, opts), do: verify_cwt(token, trusted, opts)
  defp verify_status_list_by_format(:jwt, token, trusted, opts), do: verify(token, trusted, opts)

  defp normalize_status_error(reason) when reason in [:invalid_signature, :invalid_key, :algorithm_key_mismatch],
    do: :invalid_status_list_signature

  defp normalize_status_error(reason), do: reason

  defp maybe_put_reference_cert(opts, nil), do: opts
  defp maybe_put_reference_cert(opts, cert) when is_binary(cert), do: Keyword.put(opts, :reference_certificate, cert)

  defp resolve_trust(trusted, uri, opts) do
    cond do
      is_binary(Keyword.get(opts, :reference_certificate)) ->
        {:ok, nil}

      Keyword.has_key?(opts, :trusted_certificates) ->
        {:ok, nil}

      true ->
        trusted_jwks(trusted, uri)
    end
  end

  defp parse_revocation_reference(status_claim) when is_map(status_claim) do
    has_status_list = not is_nil(MapParams.fetch(status_claim, :status_list))
    has_identifier_list = not is_nil(MapParams.fetch(status_claim, :identifier_list))

    case {has_status_list, has_identifier_list} do
      {true, false} -> parse_status_list_ref(MapParams.fetch(status_claim, :status_list))
      {false, true} -> parse_identifier_list_ref(MapParams.fetch(status_claim, :identifier_list))
      _other -> {:error, :invalid_status_reference}
    end
  end

  defp parse_status_list_ref(status_list) when is_map(status_list) do
    with idx when is_integer(idx) and idx >= 0 <- MapParams.fetch(status_list, :idx),
         uri when is_binary(uri) and uri != "" <- MapParams.fetch(status_list, :uri),
         {:ok, cert} <- optional_certificate_bytes(MapParams.fetch(status_list, :certificate)) do
      {:ok, :status_list, uri, idx, cert}
    else
      _other -> {:error, :invalid_status_reference}
    end
  end

  defp parse_status_list_ref(_other), do: {:error, :invalid_status_reference}

  defp parse_identifier_list_ref(identifier_list) when is_map(identifier_list) do
    with {:ok, id_bytes} <- required_raw_bytes(MapParams.fetch(identifier_list, :id)),
         uri when is_binary(uri) and uri != "" <- MapParams.fetch(identifier_list, :uri),
         {:ok, cert} <- optional_certificate_bytes(MapParams.fetch(identifier_list, :certificate)) do
      {:ok, :identifier_list, uri, id_bytes, cert}
    else
      _other -> {:error, :invalid_status_reference}
    end
  end

  defp parse_identifier_list_ref(_other), do: {:error, :invalid_status_reference}

  defp optional_certificate_bytes(nil), do: {:ok, nil}

  defp optional_certificate_bytes(value) do
    case required_raw_bytes(value) do
      {:ok, cert} when byte_size(cert) in 1..16_384 -> {:ok, cert}
      _other -> {:error, :invalid_status_reference}
    end
  end

  defp required_raw_bytes(value) when is_binary(value) and value != "", do: {:ok, value}

  defp required_raw_bytes(%{__struct__: CBOR.Tag, tag: :bytes, value: value}) when is_binary(value) and value != "",
    do: {:ok, value}

  defp required_raw_bytes(_other), do: {:error, :invalid_status_reference}

  if Code.ensure_loaded?(CBOR) do
    alias Attesto.Cose

    @cwt_status_list_typ "statuslist+cwt"
    @cwt_identifier_list_typ "identifierlist+cwt"

    @doc """
    Build and sign a CWT Status List Token (`statuslist+cwt`) as a CBOR-tagged
    `COSE_Sign1`.
    """
    @spec issue_cwt(String.t(), String.t(), [non_neg_integer()], keyword()) :: binary()
    def issue_cwt(pem, uri, statuses, opts \\ []) when is_binary(pem) and is_list(statuses) do
      opts = MapParams.ensure_keyword!(opts)
      uri = MapParams.required_string!(uri, :uri)
      bits = Keyword.get(opts, :bits, 1)
      compressed = statuses |> pack(bits) |> :zlib.compress()

      claims =
        %{
          2 => uri,
          6 => NumericDate.now(opts),
          65_533 => %{"bits" => bits, "lst" => %CBOR.Tag{tag: :bytes, value: compressed}}
        }
        |> maybe_put_cwt_claim(4, Keyword.get(opts, :exp))
        |> maybe_put_cwt_claim(65_534, Keyword.get(opts, :ttl))

      sign_cwt(pem, claims, Keyword.put_new(opts, :typ, @cwt_status_list_typ))
    end

    @doc """
    Build and sign an ISO 18013-5 CWT Identifier List Token (`identifierlist+cwt`)
    as a CBOR-tagged `COSE_Sign1`.
    """
    @spec issue_identifier_list_cwt(String.t(), String.t(), [binary()] | map(), keyword()) :: binary()
    def issue_identifier_list_cwt(pem, uri, identifiers, opts \\ []) when is_binary(pem) do
      opts = MapParams.ensure_keyword!(opts)
      uri = MapParams.required_string!(uri, :uri)

      identifiers_map =
        case identifiers do
          list when is_list(list) ->
            Map.new(list, fn id when is_binary(id) and id != "" ->
              {%CBOR.Tag{tag: :bytes, value: id}, %{}}
            end)

          map when is_map(map) ->
            map
        end

      claims =
        %{
          2 => uri,
          6 => NumericDate.now(opts),
          65_530 => %{"identifiers" => identifiers_map}
        }
        |> maybe_put_cwt_claim(4, Keyword.get(opts, :exp))
        |> maybe_put_cwt_claim(65_534, Keyword.get(opts, :ttl))

      sign_cwt(pem, claims, Keyword.put_new(opts, :typ, @cwt_identifier_list_typ))
    end

    @doc """
    Verify and decode a CWT Status List Token (`statuslist+cwt` / `application/statuslist+cwt`).
    """
    @spec verify_cwt(binary(), term(), keyword()) :: {:ok, verified()} | {:error, atom()}
    def verify_cwt(token, trusted, opts \\ [])

    def verify_cwt(token, trusted, opts) when is_binary(token) and byte_size(token) <= @max_status_list_token_bytes do
      opts = MapParams.ensure_keyword!(opts)

      with {:ok, claims} <- verify_cwt_envelope(token, trusted, @cwt_status_list_typ, opts) do
        decode_cwt_status_list(claims)
      end
    end

    def verify_cwt(_token, _trusted, _opts), do: {:error, :invalid_signature}

    @doc """
    Verify and decode an ISO 18013-5 CWT Identifier List Token (`identifierlist+cwt` /
    `application/identifierlist+cwt`).
    """
    @spec verify_identifier_list_cwt(binary(), term(), keyword()) ::
            {:ok, verified_identifier_list()} | {:error, atom()}
    def verify_identifier_list_cwt(token, trusted, opts \\ [])

    def verify_identifier_list_cwt(token, trusted, opts)
        when is_binary(token) and byte_size(token) <= @max_status_list_token_bytes do
      opts = MapParams.ensure_keyword!(opts)

      with {:ok, claims} <- verify_cwt_envelope(token, trusted, @cwt_identifier_list_typ, opts) do
        decode_cwt_identifier_list(claims)
      end
    end

    def verify_identifier_list_cwt(_token, _trusted, _opts), do: {:error, :invalid_signature}

    defp sign_cwt(pem, claims, opts) do
      sign_opts =
        [
          typ: Keyword.fetch!(opts, :typ),
          tagged: Keyword.get(opts, :tagged, true)
        ]
        |> maybe_put_opt(:x5chain, Keyword.get(opts, :x5chain))
        |> maybe_put_opt(:protected_x5chain, Keyword.get(opts, :protected_x5chain))

      Cose.sign1(pem, CBOR.encode(claims), sign_opts)
    end

    defp maybe_put_opt(opts, _key, nil), do: opts
    defp maybe_put_opt(opts, key, value), do: Keyword.put(opts, key, value)

    defp maybe_put_cwt_claim(claims, _key, nil), do: claims
    defp maybe_put_cwt_claim(claims, key, value), do: Map.put(claims, key, value)

    defp verify_cwt_envelope(token, trusted, expected_typ, opts) do
      with {:ok, protected, unprotected} <- Cose.peek_headers(token, allow_tagged: true),
           :ok <- check_cwt_typ(protected, expected_typ),
           {:ok, candidates} <- cwt_verification_keys(protected, unprotected, trusted, opts),
           {:ok, payload} <- verify_cwt_with_candidates(token, candidates, opts),
           {:ok, claims} <- decode_cwt_claims(payload),
           :ok <- check_cwt_temporal(claims, opts) do
        {:ok, claims}
      end
    end

    defp check_cwt_typ(protected, expected_typ) do
      if Claims.typ_matches?(Map.get(protected, 16), [expected_typ], normalization: :application_subtype),
        do: :ok,
        else: {:error, :invalid_typ}
    end

    defp cwt_verification_keys(protected, unprotected, trusted, opts) do
      cond do
        is_binary(Keyword.get(opts, :reference_certificate)) ->
          cwt_reference_certificate_keys(protected, unprotected, Keyword.fetch!(opts, :reference_certificate))

        Keyword.has_key?(opts, :trusted_certificates) ->
          trust_opts = opts |> Keyword.put_new(:haip, true) |> Keyword.put(:purpose, :generic)

          with {:ok, chain} <- cwt_x5chain(protected, unprotected),
               {:ok, verified} <- X509.verify(chain, trust_opts) do
            {:ok, [verified.public_key]}
          end

        true ->
          case cwt_key_candidates(trusted) do
            [_ | _] = keys -> {:ok, keys}
            [] -> {:error, :invalid_key}
          end
      end
    end

    defp cwt_reference_certificate_keys(protected, unprotected, ref_cert) do
      chain_result =
        if Map.has_key?(protected, 33) or Map.has_key?(unprotected, 33) do
          cwt_x5chain(protected, unprotected)
        else
          {:ok, [ref_cert]}
        end

      with {:ok, chain} <- chain_result,
           {:ok, verified} <-
             X509.verify(chain,
               trusted_certificates: [ref_cert],
               purpose: :generic,
               haip: false
             ) do
        {:ok, [verified.public_key]}
      end
    end

    defp cwt_x5chain(protected, unprotected) do
      raw =
        cond do
          Map.has_key?(protected, 33) -> Map.get(protected, 33)
          Map.has_key?(unprotected, 33) -> Map.get(unprotected, 33)
          true -> nil
        end

      decode_cwt_x5chain(raw)
    end

    defp decode_cwt_x5chain(%CBOR.Tag{tag: :bytes} = cert), do: decode_cwt_x5chain([cert])

    defp decode_cwt_x5chain(chain) when is_list(chain) do
      max_chain = X509.max_chain_length()

      if length(chain) in 1..max_chain and Enum.all?(chain, &cwt_cert_bytes?/1) do
        {:ok, Enum.map(chain, & &1.value)}
      else
        {:error, :invalid_certificate}
      end
    end

    defp decode_cwt_x5chain(_other), do: {:error, :invalid_certificate}

    defp cwt_cert_bytes?(%CBOR.Tag{tag: :bytes, value: der}) when is_binary(der) do
      byte_size(der) in 1..X509.max_cert_bytes()
    end

    defp cwt_cert_bytes?(_other), do: false

    defp cwt_key_candidates(%{"keys" => keys}) when is_list(keys), do: keys
    defp cwt_key_candidates(keys) when is_list(keys), do: keys
    defp cwt_key_candidates(%{} = jwk), do: [jwk]
    defp cwt_key_candidates(pem) when is_binary(pem), do: [pem]
    defp cwt_key_candidates(_other), do: []

    defp verify_cwt_with_candidates(token, candidates, opts) do
      accepted_algs = Keyword.get(opts, :accepted_algs, ["ES256", "ES384", "ES512"])
      cose_opts = [allow_tagged: true, accepted_algs: accepted_algs]

      Enum.reduce_while(candidates, {:error, :invalid_signature}, fn key, _acc_error ->
        case Cose.verify1(token, key, cose_opts) do
          {:ok, payload} ->
            {:halt, {:ok, payload}}

          {:error, reason} when reason in [:invalid_key, :invalid_signature, :algorithm_key_mismatch] ->
            {:cont, {:error, :invalid_signature}}

          {:error, reason} ->
            {:halt, {:error, reason}}
        end
      end)
    end

    defp decode_cwt_claims(payload) when is_binary(payload) do
      case Attesto.StrictCBOR.decode(payload) do
        {:ok, claims} when is_map(claims) and not is_struct(claims) -> {:ok, claims}
        _other -> {:error, :invalid_status_list}
      end
    end

    defp check_cwt_temporal(claims, opts) do
      now = NumericDate.now(opts, default: :system, invalid_override: :fallback)
      leeway = Keyword.get(opts, :leeway, @expiry_leeway_seconds)

      with :ok <- check_jwt_iat(Map.fetch(claims, 6), now, leeway, true),
           :ok <- check_jwt_exp(Map.fetch(claims, 4), now, leeway) do
        check_optional_ttl(Map.fetch(claims, 65_534))
      end
    end

    defp decode_cwt_status_list(%{2 => sub, 65_533 => %{"bits" => bits, "lst" => lst}} = claims)
         when is_binary(sub) and sub != "" and bits in @valid_bits do
      with {:ok, compressed} <- required_raw_bytes(lst),
           {:ok, packed} <- inflate(compressed) do
        {:ok, %{bits: bits, statuses_binary: packed, sub: sub, claims: claims}}
      else
        {:error, _reason} -> {:error, :invalid_status_list}
      end
    end

    defp decode_cwt_status_list(_claims), do: {:error, :invalid_status_list}

    defp decode_cwt_identifier_list(%{2 => sub, 65_530 => %{"identifiers" => identifiers}} = claims)
         when is_binary(sub) and sub != "" and is_map(identifiers) and not is_struct(identifiers) do
      case decode_identifier_keys(Map.keys(identifiers), []) do
        {:ok, id_set} -> {:ok, %{identifiers: id_set, sub: sub, claims: claims}}
        {:error, _reason} = error -> error
      end
    end

    defp decode_cwt_identifier_list(_claims), do: {:error, :invalid_identifier_list}

    defp decode_identifier_keys([], acc), do: {:ok, MapSet.new(acc)}

    defp decode_identifier_keys([key | rest], acc) do
      case required_raw_bytes(key) do
        {:ok, bytes} -> decode_identifier_keys(rest, [bytes | acc])
        {:error, _reason} -> {:error, :invalid_identifier_list}
      end
    end
  else
    @dep_error "Attesto.StatusList CWT functions require the optional :cbor dependency. " <>
                 "Add {:cbor, \"~> 1.0\"} to your deps."

    def issue_cwt(_pem, _uri, _statuses, _opts \\ []), do: raise(@dep_error)
    def issue_identifier_list_cwt(_pem, _uri, _identifiers, _opts \\ []), do: raise(@dep_error)
    def verify_cwt(_token, _trusted, _opts \\ []), do: raise(@dep_error)
    def verify_identifier_list_cwt(_token, _trusted, _opts \\ []), do: raise(@dep_error)
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

  defp fetch_token(resolver, uri, media_type \\ @accept_status_list_jwt) do
    result =
      cond do
        is_function(resolver, 2) -> resolver.(uri, media_type)
        is_function(resolver, 1) -> resolver.(uri)
      end

    case result do
      {:ok, token} when is_binary(token) -> {:ok, token}
      {:ok, _token} -> {:error, :invalid_status_list_token}
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_status_list_token}
    end
  rescue
    _ -> {:error, :status_list_fetch_failed}
  catch
    _, _ -> {:error, :status_list_fetch_failed}
  end

  defp trusted_jwks(resolver, uri) when is_function(resolver, 1) do
    case resolver.(uri) do
      {:ok, jwks} when is_map(jwks) or is_list(jwks) or is_binary(jwks) -> {:ok, jwks}
      {:error, _reason} = error -> error
      jwks when is_map(jwks) or is_list(jwks) or is_binary(jwks) -> {:ok, jwks}
      _other -> {:error, :invalid_jwks}
    end
  end

  defp trusted_jwks(jwks, _uri) when is_map(jwks) or is_list(jwks) or is_binary(jwks), do: {:ok, jwks}
  defp trusted_jwks(_jwks, _uri), do: {:error, :invalid_jwks}

  defp matching_subject(uri, uri), do: :ok
  defp matching_subject(_subject, _uri), do: {:error, :status_list_uri_mismatch}

  defp read_status(packed, bits, idx) do
    {:ok, status_at(packed, bits, idx)}
  rescue
    ArgumentError -> {:error, :status_index_out_of_range}
  end
end
