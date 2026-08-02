defmodule Attesto.JWS do
  @moduledoc false

  alias Attesto.{Key, SigningAlg, Thumbprint}

  @type compact_segments :: %{
          protected_segment: binary(),
          payload_segment: binary(),
          signature_segment: binary()
        }

  @type verification_candidate :: {term(), binary(), JOSE.JWK.t()}

  @type signing_context :: %{
          pem: binary(),
          jwk: JOSE.JWK.t(),
          alg: binary(),
          kid: binary()
        }

  @doc false
  @spec decode_compact(binary(), keyword()) ::
          {:ok, compact_segments()}
          | {:error, :malformed_compact | :non_canonical_base64url}
  def decode_compact(jwt, opts \\ [])

  def decode_compact(jwt, opts) when is_binary(jwt) and is_list(opts) do
    canonical? = Keyword.get(opts, :canonical, true)
    allow_empty_signature? = Keyword.get(opts, :allow_empty_signature, false)

    case :binary.split(jwt, ".", [:global]) do
      [protected, payload, signature] ->
        decode_compact_segments(
          protected,
          payload,
          signature,
          canonical?,
          allow_empty_signature?
        )

      _ ->
        {:error, :malformed_compact}
    end
  rescue
    _ -> {:error, :malformed_compact}
  end

  def decode_compact(_jwt, _opts), do: {:error, :malformed_compact}

  defp decode_compact_segments(protected, payload, signature, canonical?, allow_empty_signature?) do
    with :ok <- check_empty_signature(signature, allow_empty_signature?),
         :ok <- decode_segments([protected, payload, signature], canonical?) do
      {:ok,
       %{
         protected_segment: protected,
         payload_segment: payload,
         signature_segment: signature
       }}
    end
  end

  defp check_empty_signature("", false), do: {:error, :malformed_compact}
  defp check_empty_signature(_signature, _allow_empty_signature), do: :ok

  @doc false
  @spec peek_json(binary(), :protected | :payload, keyword()) ::
          {:ok, map()}
          | {:error, :malformed_compact | :non_canonical_base64url | :invalid_json}
  def peek_json(jwt, segment, opts \\ [])

  def peek_json(jwt, segment, opts) when is_binary(jwt) and segment in [:protected, :payload] and is_list(opts) do
    with {:ok, compact} <-
           decode_compact(jwt,
             canonical: Keyword.get(opts, :canonical, true),
             # A peek must let the caller inspect an unsecured JWS header and
             # return its protocol-specific `alg=none` error before JOSE runs.
             allow_empty_signature: Keyword.get(opts, :allow_empty_signature, true)
           ),
         encoded = Map.fetch!(compact, segment_key(segment)),
         {:ok, bytes} <- decode_segment(encoded),
         {:ok, map} <- decode_json_map(bytes) do
      {:ok, map}
    else
      {:error, _reason} = error -> error
    end
  end

  def peek_json(_jwt, _segment, _opts), do: {:error, :malformed_compact}

  @doc false
  @spec reject_unsupported_crit(map(), keyword()) :: :ok | {:error, :unsupported_crit}
  def reject_unsupported_crit(header, opts \\ [])

  def reject_unsupported_crit(header, opts) when is_map(header) and is_list(opts) do
    supported = Keyword.get(opts, :supported, [])

    case Map.fetch(header, "crit") do
      :error ->
        :ok

      {:ok, crit} when is_list(crit) and crit != [] ->
        if Enum.all?(crit, &(is_binary(&1) and &1 in supported)),
          do: :ok,
          else: {:error, :unsupported_crit}

      _ ->
        # An empty or non-array `crit` member is malformed, even when the
        # caller understands no critical extensions.
        {:error, :unsupported_crit}
    end
  end

  def reject_unsupported_crit(_header, _opts), do: {:error, :unsupported_crit}

  @doc """
  Build the trusted candidates used by strict JWT verification.

  The returned tuples retain the input order and are `{kid, alg, jwk}`. The
  default map builder derives an algorithm from each JWK's `alg` member or
  key material and validates that algorithm against the key. Passing `alg:`
  deliberately uses one presented algorithm for every map; SD-JWT issuer
  verification uses that mode for compatibility with its existing policy.

  Options:

    * `:kid` narrows the result after conversion and algorithm filtering.
    * `:accepted_algs` filters algorithms; an empty list means no filter.
    * `:fapi?` applies `SigningAlg.fapi_compatible?/2` after algorithm
      filtering.
    * `:malformed_key` is `:reject_set` (default), `:skip`, or `:raise`.
      The first returns an empty set when any map is malformed, the second
      drops only that map, and the last lets a custom builder's exception
      retain its caller-visible behavior.
    * `:candidate_builder` can build a candidate from non-JWK inputs, such as
      a PEM. Its result must be a `{kid, alg, jwk}` tuple.
  """
  @spec verification_candidates(term(), keyword()) :: [verification_candidate()]
  def verification_candidates(keys, opts \\ []) when is_list(opts) do
    malformed_key = Keyword.get(opts, :malformed_key, :reject_set)
    validate_malformed_key!(malformed_key)

    keys
    |> normalize_verification_keys()
    |> Enum.reduce_while([], &reduce_verification_candidate(&1, &2, opts, malformed_key))
    |> finish_verification_candidates(opts)
  end

  @doc """
  Verify a compact JWT against candidates in order using a singleton strict
  algorithm allowlist for each candidate.

  `:terminal_error` is returned when no candidate verifies. A JOSE result
  other than a successful result or `{false, _, _}` is controlled by
  `:malformed_result` (`:halt` or `:continue`) and `:malformed_error`.
  `:claims_map?` treats a successful JOSE result with non-map claims as a
  malformed result when set.
  `:return_key?` optionally includes the successful candidate in the result.
  """
  @spec verify_strict(binary(), [verification_candidate()], keyword()) ::
          {:ok, map()} | {:ok, map(), verification_candidate()} | {:error, atom()}
  def verify_strict(jwt, candidates, opts \\ [])

  def verify_strict(jwt, candidates, opts) when is_binary(jwt) and is_list(candidates) and is_list(opts) do
    terminal_error = Keyword.get(opts, :terminal_error, :invalid_signature)
    malformed_result = Keyword.get(opts, :malformed_result, :halt)
    claims_map? = Keyword.get(opts, :claims_map?, false)
    return_key? = Keyword.get(opts, :return_key?, false)

    validate_verification_result_options!(malformed_result, claims_map?, return_key?)

    Enum.reduce_while(candidates, {:error, terminal_error}, &verify_candidate(&1, &2, jwt, opts))
  end

  def verify_strict(_jwt, _candidates, _opts), do: {:error, :invalid_signature}

  defp decode_segments(segments, canonical?) do
    Enum.reduce_while(segments, :ok, fn segment, :ok ->
      case check_segment(segment, canonical?) do
        :ok -> {:cont, :ok}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp check_segment(segment, canonical?) do
    with {:ok, decoded} <- decode_segment(segment),
         :ok <- check_canonical_segment(segment, decoded, canonical?) do
      :ok
    else
      {:error, :invalid_base64url} -> {:error, :malformed_compact}
      {:error, _reason} = error -> error
    end
  end

  defp check_canonical_segment(_segment, _decoded, false), do: :ok

  defp check_canonical_segment(segment, decoded, true) do
    if Base.url_encode64(decoded, padding: false) == segment,
      do: :ok,
      else: {:error, :non_canonical_base64url}
  end

  defp decode_segment(segment) do
    case Base.url_decode64(segment, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64url}
    end
  rescue
    _ -> {:error, :invalid_base64url}
  end

  defp decode_json_map(bytes) do
    case JSON.decode(bytes) do
      {:ok, %{} = map} -> {:ok, map}
      _ -> {:error, :invalid_json}
    end
  rescue
    _ -> {:error, :invalid_json}
  end

  defp segment_key(:protected), do: :protected_segment
  defp segment_key(:payload), do: :payload_segment

  defp normalize_verification_keys(%{"keys" => keys}) when is_list(keys), do: keys
  defp normalize_verification_keys(keys) when is_list(keys), do: keys
  defp normalize_verification_keys(%{} = jwk), do: [jwk]
  defp normalize_verification_keys(_keys), do: []

  defp build_verification_candidate(key, opts, :raise) do
    {:ok, build_candidate!(key, opts)}
  end

  defp build_verification_candidate(key, opts, malformed_key) do
    {:ok, build_candidate!(key, opts)}
  rescue
    _ -> malformed_candidate(malformed_key)
  catch
    _, _ -> malformed_candidate(malformed_key)
  end

  defp reduce_verification_candidate(key, acc, opts, malformed_key) do
    case build_verification_candidate(key, opts, malformed_key) do
      {:ok, candidate} -> accepted_candidate_step(candidate, acc, opts, malformed_key)
      :skip -> {:cont, acc}
      :reject_set -> {:halt, :reject_set}
    end
  end

  defp accepted_candidate_step(candidate, acc, opts, malformed_key) do
    case allow_verification_candidate(candidate, opts, malformed_key) do
      true -> {:cont, [candidate | acc]}
      false -> {:cont, acc}
      :skip -> {:cont, acc}
      :reject_set -> {:halt, :reject_set}
    end
  end

  defp verify_candidate(candidate, acc, jwt, opts) do
    case JOSE.JWT.verify_strict(candidate_jwk(candidate), [candidate_alg(candidate)], jwt) do
      {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> verified_candidate_result(claims, candidate, acc, opts)
      {false, _jwt, _jws} -> {:cont, acc}
      _other -> malformed_candidate_result(acc, opts)
    end
  end

  defp verified_candidate_result(claims, candidate, acc, opts) do
    claims_map? = Keyword.get(opts, :claims_map?, false)
    malformed_result = Keyword.get(opts, :malformed_result, :halt)
    malformed_error = Keyword.get(opts, :malformed_error, Keyword.get(opts, :terminal_error, :invalid_signature))
    return_key? = Keyword.get(opts, :return_key?, false)

    if claims_map? and not is_map(claims),
      do: malformed_verification_result(acc, malformed_result, malformed_error),
      else: {:halt, successful_verification(claims, candidate, return_key?)}
  end

  defp malformed_candidate_result(acc, opts) do
    malformed_result = Keyword.get(opts, :malformed_result, :halt)
    malformed_error = Keyword.get(opts, :malformed_error, Keyword.get(opts, :terminal_error, :invalid_signature))
    malformed_verification_result(acc, malformed_result, malformed_error)
  end

  defp build_candidate!(key, opts) do
    candidate =
      case Keyword.get(opts, :candidate_builder) do
        builder when is_function(builder, 1) -> builder.(key)
        nil -> map_candidate!(key, opts)
        _other -> raise ArgumentError, ":candidate_builder must be a unary function"
      end

    validate_candidate!(candidate)
  end

  defp map_candidate!(jwk_map, opts) when is_map(jwk_map) do
    jwk = JOSE.JWK.from_map(jwk_map)

    alg =
      case Keyword.fetch(opts, :alg) do
        {:ok, fixed_alg} when is_binary(fixed_alg) -> fixed_alg
        {:ok, _other} -> raise ArgumentError, ":alg must be a string"
        :error -> Map.get(jwk_map, "alg") || SigningAlg.infer(jwk)
      end

    alg = if Keyword.has_key?(opts, :alg), do: alg, else: SigningAlg.validate_for_key!(alg, jwk)
    {Map.get(jwk_map, "kid"), alg, jwk}
  end

  defp map_candidate!(_jwk_map, _opts), do: raise(ArgumentError, "verification candidate must be a JWK map")

  defp validate_candidate!({kid, alg, %JOSE.JWK{} = jwk}) when is_binary(alg), do: {kid, alg, jwk}

  defp validate_candidate!(_candidate), do: raise(ArgumentError, "verification candidate must be {kid, alg, jwk}")

  defp candidate_allowed?({_kid, alg, jwk}, opts) do
    accepted_algs = Keyword.get(opts, :accepted_algs, [])
    accepted? = accepted_algs == [] or alg in accepted_algs
    fapi? = Keyword.get(opts, :fapi?, false)
    accepted? and (not fapi? or SigningAlg.fapi_compatible?(alg, jwk))
  end

  defp allow_verification_candidate(candidate, opts, :raise), do: candidate_allowed?(candidate, opts)

  defp allow_verification_candidate(candidate, opts, malformed_key) do
    candidate_allowed?(candidate, opts)
  rescue
    _ -> malformed_candidate(malformed_key)
  catch
    _, _ -> malformed_candidate(malformed_key)
  end

  defp finish_verification_candidates(:reject_set, _opts), do: []

  defp finish_verification_candidates(candidates, opts) do
    candidates
    |> Enum.reverse()
    |> filter_verification_kid(Keyword.get(opts, :kid))
  end

  defp filter_verification_kid(candidates, nil), do: candidates
  defp filter_verification_kid(candidates, kid), do: Enum.filter(candidates, &match?({^kid, _, _}, &1))

  defp malformed_candidate(:skip), do: :skip
  defp malformed_candidate(:reject_set), do: :reject_set

  defp successful_verification(claims, candidate, true), do: {:ok, claims, candidate}
  defp successful_verification(claims, _candidate, false), do: {:ok, claims}

  defp malformed_verification_result(acc, :continue, _malformed_error), do: {:cont, acc}
  defp malformed_verification_result(_acc, :halt, malformed_error), do: {:halt, {:error, malformed_error}}

  defp candidate_jwk({_kid, _alg, jwk}), do: jwk
  defp candidate_alg({_kid, alg, _jwk}), do: alg

  defp validate_malformed_key!(mode) when mode in [:reject_set, :skip, :raise], do: :ok

  defp validate_malformed_key!(mode),
    do: raise(ArgumentError, ":malformed_key must be :reject_set, :skip, or :raise; got #{inspect(mode)}")

  defp validate_verification_result_options!(malformed_result, claims_map?, return_key?)
       when malformed_result in [:halt, :continue] and is_boolean(claims_map?) and is_boolean(return_key?), do: :ok

  defp validate_verification_result_options!(_malformed_result, _claims_map?, _return_key?),
    do:
      raise(ArgumentError, ":malformed_result must be :halt or :continue and :claims_map?/return_key? must be boolean")

  @doc false
  @spec current_signing_context(module()) :: signing_context()
  def current_signing_context(keystore) when is_atom(keystore) do
    pem = keystore.signing_pem()
    jwk = Key.signing_jwk(pem)
    alg = SigningAlg.for_jwk(keystore, jwk, signing?: true)
    {:ok, kid} = Thumbprint.of_jwk(jwk)

    %{pem: pem, jwk: jwk, alg: alg, kid: kid}
  end

  @doc """
  Sign claims with a keystore's current signing key.

  The key is loaded exactly once from the PEM returned by signing_pem/0.
  alg and kid are derived from that same parsed key, while typ and
  extra_protected carry caller-specific protected-header members. The helper
  owns alg, kid, and typ; collisions in extra_protected raise ArgumentError.

  signing_context is an internal escape hatch for a caller that already needs
  the current parsed key to construct key-dependent claims. It must be a
  context returned by current_signing_context/1 and avoids reading a rotating
  keystore a second time.
  """
  @spec sign_current(module(), map(), keyword()) :: String.t()
  def sign_current(keystore, claims, opts \\ [])

  def sign_current(keystore, claims, opts) when is_atom(keystore) and is_map(claims) and is_list(opts) do
    context = Keyword.get(opts, :signing_context) || current_signing_context(keystore)
    sign_with_context(context, claims, opts)
  end

  defp sign_with_context(%{jwk: %JOSE.JWK{}, alg: alg, kid: kid} = context, claims, opts)
       when is_map(claims) and is_list(opts) do
    header = current_header(alg, kid, opts)
    sign_compact_with_jwk(context.jwk, header, claims)
  end

  defp sign_with_context(_context, _claims, _opts),
    do: raise(ArgumentError, ":signing_context must come from current_signing_context/1")

  defp current_header(alg, kid, opts) do
    typ = Keyword.get(opts, :typ)
    extra_protected = Keyword.get(opts, :extra_protected, %{})

    validate_typ!(typ)
    validate_extra_protected!(extra_protected)

    %{"alg" => alg, "kid" => kid}
    |> maybe_put_typ(typ)
    |> Map.merge(extra_protected)
  end

  defp maybe_put_typ(header, nil), do: header
  defp maybe_put_typ(header, typ), do: Map.put(header, "typ", typ)

  defp validate_typ!(typ) when is_binary(typ) or is_nil(typ), do: :ok

  defp validate_typ!(typ), do: raise(ArgumentError, ":typ must be a string or nil; got #{inspect(typ)}")

  defp validate_extra_protected!(extra) when is_map(extra) do
    if Enum.any?(Map.keys(extra), &reserved_header_key?/1) do
      raise ArgumentError, ":extra_protected cannot override alg, kid, or typ"
    end

    :ok
  end

  defp validate_extra_protected!(extra),
    do: raise(ArgumentError, ":extra_protected must be a map; got #{inspect(extra)}")

  defp reserved_header_key?(key) when key in ["alg", "kid", "typ", :alg, :kid, :typ], do: true
  defp reserved_header_key?(_key), do: false

  @doc false
  @spec sign_compact(String.t(), map(), map()) :: String.t()
  def sign_compact(pem, header, claims) when is_binary(pem) and is_map(header) and is_map(claims) do
    header |> Map.fetch!("alg") |> SigningAlg.validate!()
    pem |> Key.signing_jwk() |> sign_compact_with_jwk(header, claims)
  end

  defp sign_compact_with_jwk(jwk, header, claims) do
    alg = header |> Map.fetch!("alg") |> SigningAlg.validate!()
    payload = JSON.encode!(claims)

    case alg do
      "PS" <> _ -> sign_ps_compact(jwk, header, payload, alg)
      _ -> sign_jose_compact(jwk, header, payload)
    end
  end

  defp sign_jose_compact(jwk, header, payload) do
    signed =
      jwk
      |> JOSE.JWS.sign(payload, header)

    {_protected_header, compact} = JOSE.JWS.compact(signed)
    compact
  end

  # RFC 7518 §3.5: RSASSA-PSS salt length MUST equal the hash output length.
  # JOSE 1.11 signs PS* with OpenSSL's maximum salt length, which it can verify
  # itself but strict FAPI/OIDF validators correctly reject.
  defp sign_ps_compact(jwk, header, payload, alg) do
    encoded_header = encode_segment(header)
    encoded_payload = Base.url_encode64(payload, padding: false)
    signing_input = encoded_header <> "." <> encoded_payload

    signature =
      :public_key.sign(
        signing_input,
        hash_alg(alg),
        private_key(jwk),
        pss_opts(alg)
      )

    signing_input <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp encode_segment(value) do
    value
    |> JSON.encode!()
    |> Base.url_encode64(padding: false)
  end

  defp private_key(jwk), do: jwk |> JOSE.JWK.to_key() |> elem(1)

  defp pss_opts(alg) do
    [
      {:rsa_padding, :rsa_pkcs1_pss_padding},
      {:rsa_pss_saltlen, salt_length(alg)}
    ]
  end

  defp hash_alg("PS256"), do: :sha256
  defp hash_alg("PS384"), do: :sha384
  defp hash_alg("PS512"), do: :sha512

  defp salt_length("PS256"), do: 32
  defp salt_length("PS384"), do: 48
  defp salt_length("PS512"), do: 64
end
