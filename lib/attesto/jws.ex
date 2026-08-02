defmodule Attesto.JWS do
  @moduledoc false

  alias Attesto.Key
  alias Attesto.SigningAlg

  @type compact_segments :: %{
          protected_segment: binary(),
          payload_segment: binary(),
          signature_segment: binary()
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

  @doc false
  @spec sign_compact(String.t(), map(), map()) :: String.t()
  def sign_compact(pem, header, claims) when is_binary(pem) and is_map(header) and is_map(claims) do
    alg = header |> Map.fetch!("alg") |> SigningAlg.validate!()
    payload = JSON.encode!(claims)

    case alg do
      "PS" <> _ -> sign_ps_compact(pem, header, payload, alg)
      _ -> sign_jose_compact(pem, header, payload)
    end
  end

  defp sign_jose_compact(pem, header, payload) do
    signed =
      pem
      |> Key.signing_jwk()
      |> JOSE.JWS.sign(payload, header)

    {_protected_header, compact} = JOSE.JWS.compact(signed)
    compact
  end

  # RFC 7518 §3.5: RSASSA-PSS salt length MUST equal the hash output length.
  # JOSE 1.11 signs PS* with OpenSSL's maximum salt length, which it can verify
  # itself but strict FAPI/OIDF validators correctly reject.
  defp sign_ps_compact(pem, header, payload, alg) do
    encoded_header = encode_segment(header)
    encoded_payload = Base.url_encode64(payload, padding: false)
    signing_input = encoded_header <> "." <> encoded_payload

    signature =
      :public_key.sign(
        signing_input,
        hash_alg(alg),
        private_key(pem),
        pss_opts(alg)
      )

    signing_input <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp encode_segment(value) do
    value
    |> JSON.encode!()
    |> Base.url_encode64(padding: false)
  end

  defp private_key(pem) do
    pem
    |> :public_key.pem_decode()
    |> List.first()
    |> :public_key.pem_entry_decode()
  end

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
