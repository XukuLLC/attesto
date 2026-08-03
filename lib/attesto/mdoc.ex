if Code.ensure_loaded?(CBOR) do
  defmodule Attesto.Mdoc do
    @moduledoc """
    Issue and verify ISO 18013-5 mdoc credentials and OID4VP mdoc
    presentations.

    Issuance builds the MobileSecurityObject (MSO), binds the holder's device
    key, and signs issuer authentication with ES256 `COSE_Sign1`. `verify/3`
    checks issuer signatures, item digests, document type, and validity for a
    bare `IssuerSigned` structure.

    `verify_device_response/4` additionally verifies an OID4VP presentation: a
    full ISO 18013-5 `DeviceResponse` whose `DeviceSigned.deviceAuth` is an
    ES256 `COSE_Sign1` (detached payload) over `DeviceAuthentication =
    ["DeviceAuthentication", SessionTranscript, DocType,
    DeviceNameSpacesBytes]`, where `SessionTranscript`'s `Handover` is OID4VP's
    `OpenID4VPHandover` (redirect-flow form, per the OID4VP 1.0 "Handover and
    SessionTranscript Definitions"). `COSE_Mac0` device authentication is not
    supported.

    `peek_doc_type/1` reads an unverified `docType` out of a `DeviceResponse`
    for issuer-key resolution ahead of verification; see `Attesto.VpToken`.
    """

    alias Attesto.{Cose, JWS, NumericDate, SecureCompare, Thumbprint}

    @clock_skew_seconds 60
    @digest_algorithm "SHA-256"
    @minimum_random_bytes 16

    @type validity :: %{
            signed: integer(),
            valid_from: integer(),
            valid_until: integer()
          }

    @type verified :: %{
            doc_type: String.t(),
            namespaces: %{String.t() => %{String.t() => term()}},
            device_key: map(),
            validity: validity()
          }

    @type verified_presentation :: %{
            doc_type: String.t(),
            namespaces: %{String.t() => %{String.t() => term()}},
            device_namespaces: %{String.t() => %{String.t() => term()}},
            validity: validity()
          }

    @type verify_error ::
            :digest_mismatch
            | :expired
            | :invalid_cose
            | :invalid_key
            | :invalid_mdoc
            | :invalid_signature
            | :not_yet_valid
            | :unexpected_doc_type
            | :unsupported_algorithm

    @doc """
    Issue a base64url-encoded ISO 18013-5 IssuerSigned structure.

    Required options are `:doc_type`, `:namespaces`, `:device_key`,
    `:issuer_pem`, and `:validity`. `:x5chain` optionally carries a list of
    issuer-certificate DER binaries in the COSE unprotected header.
    """
    @spec issue(keyword()) :: {:ok, String.t()} | {:error, :invalid_options}
    def issue(opts) when is_list(opts) do
      {:ok, issue!(opts)}
    rescue
      _error -> {:error, :invalid_options}
    catch
      _kind, _reason -> {:error, :invalid_options}
    end

    def issue(_opts), do: {:error, :invalid_options}

    @doc """
    Verify an IssuerSigned mdoc supplied as base64url or raw CBOR bytes.

    `trusted` is the issuer's public JWK or PEM. Set `:expected_doc_type` to
    bind verification to a requested credential type. A `:now` option may be
    supplied as Unix seconds or a `DateTime` for deterministic clock checks.
    """
    @spec verify(binary(), JOSE.JWK.t() | map() | String.t(), keyword()) ::
            {:ok, verified()} | {:error, verify_error()}
    def verify(input, trusted, opts \\ [])

    def verify(input, trusted, opts) when is_binary(input) and is_list(opts) do
      with {:ok, issuer_signed_bytes} <- issuer_signed_bytes(input),
           {:ok, issuer_signed} <- decode_complete(issuer_signed_bytes) do
        verify_issuer_signed(issuer_signed, trusted, opts)
      end
    rescue
      _error -> {:error, :invalid_mdoc}
    catch
      _kind, _reason -> {:error, :invalid_mdoc}
    end

    def verify(_input, _trusted, _opts), do: {:error, :invalid_mdoc}

    @doc """
    Verify an OID4VP mdoc presentation: a full ISO 18013-5 `DeviceResponse`
    supplied as base64url or raw CBOR bytes.

    `context` supplies the OID4VP request values needed to reconstruct the
    `OpenID4VPHandover` and `SessionTranscript`: `:client_id`, `:nonce`, and
    `:response_uri` are required. `:response_encryption_jwk` is the
    Verifier's public response-encryption key (present only for the
    `direct_post.jwt` Response Mode) and is folded in as the handover's JWK
    thumbprint; omit it for unencrypted `direct_post`.

    `trusted` and `opts` verify each document's `IssuerSigned` structure
    exactly as in `verify/3` (`:expected_doc_type` and `:now` included).
    Each document's `DeviceSigned.deviceAuth` is additionally verified as an
    ES256 `COSE_Sign1` with a detached payload, signed by the device key
    bound in that document's MSO.

    Returns one verified result per document in the `DeviceResponse`.
    """
    @spec verify_device_response(binary(), keyword(), JOSE.JWK.t() | map() | String.t(), keyword()) ::
            {:ok, [verified_presentation()]} | {:error, verify_error()}
    def verify_device_response(device_response, context, trusted, opts \\ [])

    def verify_device_response(device_response, context, trusted, opts)
        when is_binary(device_response) and is_list(context) and is_list(opts) do
      with {:ok, session_transcript} <- session_transcript(context),
           {:ok, response_bytes} <- issuer_signed_bytes(device_response),
           {:ok, response} <- decode_complete(response_bytes),
           {:ok, documents} <- device_response_documents(response) do
        verify_documents(documents, session_transcript, trusted, opts)
      end
    rescue
      _error -> {:error, :invalid_mdoc}
    catch
      _kind, _reason -> {:error, :invalid_mdoc}
    end

    def verify_device_response(_device_response, _context, _trusted, _opts), do: {:error, :invalid_mdoc}

    @doc """
    Peek an OID4VP `DeviceResponse`'s first document `docType`, supplied as
    base64url or raw CBOR bytes, without verifying any signature.

    Mirrors `Attesto.JWS.peek_json/3` peeking an SD-JWT's unverified `iss`:
    the result is UNVERIFIED input and exists only to select candidate issuer
    keys ahead of verification (e.g. for `Attesto.VpToken`'s `:resolve_issuer`
    callback). It MUST NOT be used to make a network request — the presenter
    controls this value.
    """
    @spec peek_doc_type(binary()) :: {:ok, String.t()} | {:error, :invalid_mdoc}
    def peek_doc_type(device_response) when is_binary(device_response) do
      with {:ok, response_bytes} <- issuer_signed_bytes(device_response),
           {:ok, response} <- decode_complete(response_bytes),
           {:ok, [%{"docType" => doc_type} | _rest]} <- device_response_documents(response),
           true <- is_binary(doc_type) and doc_type != "" do
        {:ok, doc_type}
      else
        _other -> {:error, :invalid_mdoc}
      end
    rescue
      _error -> {:error, :invalid_mdoc}
    catch
      _kind, _reason -> {:error, :invalid_mdoc}
    end

    def peek_doc_type(_device_response), do: {:error, :invalid_mdoc}

    defp verify_issuer_signed(issuer_signed, trusted, opts) do
      with {:ok, encoded_issuer_auth, name_spaces} <- issuer_signed_parts(issuer_signed),
           {:ok, mso_payload} <- Cose.verify1(encoded_issuer_auth, trusted, []),
           {:ok, mso} <- decode_embedded(mso_payload),
           {:ok, mso_parts} <- validate_mso(mso),
           :ok <- check_expected_doc_type(mso_parts.doc_type, opts),
           {:ok, namespaces} <- verify_namespaces(name_spaces, mso_parts.value_digests),
           :ok <- check_validity(mso_parts.validity, opts),
           {:ok, device_key} <- device_key(mso_parts.device_key) do
        {:ok,
         %{
           device_key: device_key,
           doc_type: mso_parts.doc_type,
           namespaces: namespaces,
           validity: mso_parts.validity
         }}
      end
    end

    defp device_response_documents(%{"documents" => documents, "status" => 0})
         when is_list(documents) and documents != [] do
      {:ok, documents}
    end

    defp device_response_documents(_response), do: {:error, :invalid_mdoc}

    defp verify_documents(documents, session_transcript, trusted, opts) do
      documents
      |> Enum.reduce_while({:ok, []}, fn document, {:ok, verified} ->
        case verify_document(document, session_transcript, trusted, opts) do
          {:ok, result} -> {:cont, {:ok, [result | verified]}}
          {:error, _reason} = error -> {:halt, error}
        end
      end)
      |> reverse_documents()
    end

    defp reverse_documents({:ok, verified}), do: {:ok, Enum.reverse(verified)}
    defp reverse_documents({:error, _reason} = error), do: error

    defp verify_document(
           %{"docType" => doc_type, "issuerSigned" => issuer_signed, "deviceSigned" => device_signed},
           session_transcript,
           trusted,
           opts
         )
         when is_binary(doc_type) and doc_type != "" and is_map(issuer_signed) and is_map(device_signed) do
      with {:ok, issuer_result} <- verify_issuer_signed(issuer_signed, trusted, opts),
           true <- doc_type == issuer_result.doc_type,
           {:ok, device_namespaces_bytes} <- device_namespaces_bytes(device_signed),
           {:ok, device_namespaces} <- decode_device_namespaces(device_namespaces_bytes),
           {:ok, device_signature_bytes} <- device_signature_bytes(device_signed),
           :ok <-
             Cose.verify1_detached(
               device_signature_bytes,
               device_authentication_bytes(session_transcript, doc_type, device_namespaces_bytes),
               issuer_result.device_key,
               []
             ) do
        {:ok,
         %{
           device_namespaces: device_namespaces,
           doc_type: doc_type,
           namespaces: issuer_result.namespaces,
           validity: issuer_result.validity
         }}
      else
        false -> {:error, :unexpected_doc_type}
        {:error, _reason} = error -> error
      end
    end

    defp verify_document(_document, _session_transcript, _trusted, _opts), do: {:error, :invalid_mdoc}

    defp device_namespaces_bytes(%{"nameSpaces" => %CBOR.Tag{tag: 24} = tagged}), do: {:ok, tagged}
    defp device_namespaces_bytes(_device_signed), do: {:error, :invalid_mdoc}

    defp decode_device_namespaces(tagged) do
      with {:ok, bytes} <- embedded_bytes(tagged),
           {:ok, namespaces} <- decode_complete(bytes),
           true <- is_map(namespaces) do
        {:ok, namespaces}
      else
        _other -> {:error, :invalid_mdoc}
      end
    end

    defp device_signature_bytes(%{"deviceAuth" => %{"deviceSignature" => parts}}) when is_list(parts) do
      {:ok, CBOR.encode(parts)}
    end

    defp device_signature_bytes(%{"deviceAuth" => %{"deviceMac" => _mac}}), do: {:error, :unsupported_algorithm}
    defp device_signature_bytes(_device_signed), do: {:error, :invalid_mdoc}

    defp device_authentication_bytes(session_transcript, doc_type, device_namespaces_bytes) do
      ["DeviceAuthentication", session_transcript, doc_type, device_namespaces_bytes]
      |> embedded_cbor()
      |> CBOR.encode()
    end

    # OID4VP 1.0 "Handover and SessionTranscript Definitions" (redirect flow):
    # SessionTranscript = [null, null, OpenID4VPHandover], where
    # OpenID4VPHandover = ["OpenID4VPHandover", sha256(OpenID4VPHandoverInfo)]
    # and OpenID4VPHandoverInfo = [client_id, nonce, jwkThumbprint, response_uri].
    # `jwkThumbprint` is the JWK SHA-256 thumbprint of the Verifier's response-
    # encryption key for `direct_post.jwt`, or `null` for unencrypted `direct_post`.
    defp session_transcript(context) do
      with {:ok, client_id} <- required_context_value(context, :client_id),
           {:ok, nonce} <- required_context_value(context, :nonce),
           {:ok, response_uri} <- required_context_value(context, :response_uri),
           {:ok, jwk_thumbprint} <- handover_jwk_thumbprint(context) do
        handover_info_hash =
          [client_id, nonce, jwk_thumbprint, response_uri]
          |> CBOR.encode()
          |> then(&:crypto.hash(:sha256, &1))
          |> bytes()

        {:ok, [nil, nil, ["OpenID4VPHandover", handover_info_hash]]}
      end
    end

    defp required_context_value(context, key) do
      case Keyword.get(context, key) do
        value when is_binary(value) and value != "" -> {:ok, value}
        _other -> {:error, :invalid_mdoc}
      end
    end

    defp handover_jwk_thumbprint(context) do
      case Keyword.get(context, :response_encryption_jwk) do
        nil ->
          {:ok, nil}

        jwk ->
          case Thumbprint.of_jwk(jwk) do
            {:ok, thumbprint} -> {:ok, thumbprint |> Base.url_decode64!(padding: false) |> bytes()}
            {:error, _reason} -> {:error, :invalid_key}
          end
      end
    end

    defp issue!(opts) do
      doc_type = opts |> Keyword.fetch!(:doc_type) |> validate_nonempty_string!(:doc_type)
      namespaces = opts |> Keyword.fetch!(:namespaces) |> validate_namespaces!()
      device_key = opts |> Keyword.fetch!(:device_key) |> Cose.key_to_cose()
      issuer_pem = Keyword.fetch!(opts, :issuer_pem)
      validity = opts |> Keyword.fetch!(:validity) |> validate_validity!()
      x5chain = Keyword.get(opts, :x5chain)

      {issuer_namespaces, value_digests} = build_namespaces(namespaces)
      mso = build_mso(doc_type, value_digests, device_key, validity)
      mso_payload = mso |> embedded_cbor() |> CBOR.encode()
      issuer_auth = issuer_pem |> Cose.sign1(mso_payload, x5chain: x5chain) |> decode_complete!()

      %{"issuerAuth" => issuer_auth, "nameSpaces" => issuer_namespaces}
      |> CBOR.encode()
      |> Base.url_encode64(padding: false)
    end

    defp build_namespaces(namespaces) do
      namespaces
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.reduce({%{}, %{}}, fn {namespace, elements}, {items_by_namespace, digests_by_namespace} ->
        {items, digests} = build_namespace_items(elements)

        {
          Map.put(items_by_namespace, namespace, items),
          Map.put(digests_by_namespace, namespace, digests)
        }
      end)
    end

    defp build_namespace_items(elements) do
      elements
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.with_index()
      |> Enum.reduce({[], %{}}, fn {{element_id, value}, digest_id}, {items, digests} ->
        item =
          embedded_cbor(%{
            "digestID" => digest_id,
            "elementIdentifier" => element_id,
            "elementValue" => value,
            "random" => bytes(:crypto.strong_rand_bytes(@minimum_random_bytes))
          })

        digest = item |> CBOR.encode() |> then(&:crypto.hash(:sha256, &1)) |> bytes()
        {items ++ [item], Map.put(digests, digest_id, digest)}
      end)
    end

    defp build_mso(doc_type, value_digests, device_key, validity) do
      %{
        "deviceKeyInfo" => %{"deviceKey" => device_key},
        "digestAlgorithm" => @digest_algorithm,
        "docType" => doc_type,
        "validityInfo" => %{
          "signed" => tagged_datetime(validity.signed),
          "validFrom" => tagged_datetime(validity.valid_from),
          "validUntil" => tagged_datetime(validity.valid_until)
        },
        "valueDigests" => value_digests,
        "version" => "1.0"
      }
    end

    defp issuer_signed_bytes(input) do
      if base64url?(input) do
        JWS.decode64(input)
      else
        {:ok, input}
      end
    end

    defp base64url?(input) do
      String.valid?(input) and Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, input)
    end

    defp issuer_signed_parts(%{"issuerAuth" => issuer_auth, "nameSpaces" => name_spaces})
         when is_list(issuer_auth) and is_map(name_spaces) do
      {:ok, CBOR.encode(issuer_auth), name_spaces}
    end

    defp issuer_signed_parts(_issuer_signed), do: {:error, :invalid_mdoc}

    defp decode_embedded(encoded) do
      with {:ok, tagged} <- decode_complete(encoded),
           {:ok, embedded} <- embedded_bytes(tagged),
           {:ok, value} <- decode_complete(embedded) do
        {:ok, value}
      else
        _other -> {:error, :invalid_mdoc}
      end
    end

    defp validate_mso(%{
           "deviceKeyInfo" => %{"deviceKey" => device_key},
           "digestAlgorithm" => @digest_algorithm,
           "docType" => doc_type,
           "validityInfo" => validity_info,
           "valueDigests" => value_digests,
           "version" => "1.0"
         })
         when is_binary(doc_type) and doc_type != "" and is_map(value_digests) do
      with {:ok, validity} <- parse_validity(validity_info) do
        {:ok,
         %{
           device_key: device_key,
           doc_type: doc_type,
           validity: validity,
           value_digests: value_digests
         }}
      end
    end

    defp validate_mso(%{"digestAlgorithm" => _other}), do: {:error, :unsupported_algorithm}
    defp validate_mso(_mso), do: {:error, :invalid_mdoc}

    defp parse_validity(%{"signed" => signed, "validFrom" => valid_from, "validUntil" => valid_until}) do
      with {:ok, signed_unix} <- datetime_to_unix(signed),
           {:ok, valid_from_unix} <- datetime_to_unix(valid_from),
           {:ok, valid_until_unix} <- datetime_to_unix(valid_until),
           true <- valid_from_unix <= valid_until_unix do
        {:ok,
         %{
           signed: signed_unix,
           valid_from: valid_from_unix,
           valid_until: valid_until_unix
         }}
      else
        _other -> {:error, :invalid_mdoc}
      end
    end

    defp parse_validity(_validity), do: {:error, :invalid_mdoc}

    defp datetime_to_unix(%DateTime{} = datetime), do: {:ok, DateTime.to_unix(datetime, :second)}

    defp datetime_to_unix(%CBOR.Tag{tag: 0, value: value}) when is_binary(value) do
      case DateTime.from_iso8601(value) do
        {:ok, datetime, _offset} -> {:ok, DateTime.to_unix(datetime, :second)}
        _other -> {:error, :invalid_mdoc}
      end
    end

    defp datetime_to_unix(_value), do: {:error, :invalid_mdoc}

    defp verify_namespaces(name_spaces, value_digests) do
      Enum.reduce_while(name_spaces, {:ok, %{}}, fn {namespace, items}, {:ok, verified} ->
        case verify_namespace(namespace, items, value_digests) do
          {:ok, elements} -> {:cont, {:ok, Map.put(verified, namespace, elements)}}
          {:error, _reason} = error -> {:halt, error}
        end
      end)
    end

    defp verify_namespace(namespace, items, value_digests) when is_binary(namespace) and is_list(items) do
      case Map.fetch(value_digests, namespace) do
        {:ok, namespace_digests} when is_map(namespace_digests) -> verify_items(items, namespace_digests)
        _other -> {:error, :digest_mismatch}
      end
    end

    defp verify_namespace(_namespace, _items, _value_digests), do: {:error, :invalid_mdoc}

    defp verify_items(items, expected_digests) do
      Enum.reduce_while(items, {:ok, %{}}, fn item, {:ok, elements} ->
        case verify_item(item, expected_digests, elements) do
          {:ok, verified_elements} -> {:cont, {:ok, verified_elements}}
          {:error, _reason} = error -> {:halt, error}
        end
      end)
    end

    defp verify_item(tagged_item, expected_digests, elements) do
      with {:ok, item_bytes} <- embedded_bytes(tagged_item),
           {:ok, item} <- decode_complete(item_bytes),
           {:ok, digest_id, element_id, element_value} <- issuer_signed_item(item),
           :ok <- verify_item_digest(tagged_item, expected_digests, digest_id),
           false <- Map.has_key?(elements, element_id) do
        {:ok, Map.put(elements, element_id, element_value)}
      else
        true -> {:error, :invalid_mdoc}
        {:error, _reason} = error -> error
      end
    end

    defp issuer_signed_item(%{
           "digestID" => digest_id,
           "elementIdentifier" => element_id,
           "elementValue" => element_value,
           "random" => random_value
         })
         when is_integer(digest_id) and digest_id >= 0 and is_binary(element_id) and element_id != "" do
      case byte_string(random_value) do
        {:ok, random} when byte_size(random) >= @minimum_random_bytes ->
          {:ok, digest_id, element_id, element_value}

        _other ->
          {:error, :invalid_mdoc}
      end
    end

    defp issuer_signed_item(_item), do: {:error, :invalid_mdoc}

    defp verify_item_digest(item, expected_digests, digest_id) do
      calculated = item |> CBOR.encode() |> then(&:crypto.hash(:sha256, &1))

      with {:ok, expected_value} <- Map.fetch(expected_digests, digest_id),
           {:ok, expected} <- byte_string(expected_value),
           true <- SecureCompare.equal?(calculated, expected) do
        :ok
      else
        _other -> {:error, :digest_mismatch}
      end
    end

    defp check_expected_doc_type(doc_type, opts) do
      case Keyword.get(opts, :expected_doc_type) do
        nil -> :ok
        ^doc_type -> :ok
        expected when is_binary(expected) -> {:error, :unexpected_doc_type}
        _other -> {:error, :invalid_mdoc}
      end
    end

    defp check_validity(validity, opts) do
      now = NumericDate.now(opts, invalid_override: :fallback)

      cond do
        not NumericDate.not_expired?(validity.valid_until, now, leeway: @clock_skew_seconds) ->
          {:error, :expired}

        not NumericDate.not_before_reached?(validity.valid_from, now, skew: @clock_skew_seconds) ->
          {:error, :not_yet_valid}

        true ->
          :ok
      end
    end

    defp device_key(cose_key) do
      {:ok, Cose.cose_to_key(cose_key)}
    rescue
      _error -> {:error, :invalid_mdoc}
    end

    defp validate_nonempty_string!(value, _name) when is_binary(value) and value != "", do: value

    defp validate_nonempty_string!(_value, name) do
      raise ArgumentError, ":#{name} must be a non-empty string"
    end

    defp validate_namespaces!(namespaces) when is_map(namespaces) do
      Enum.each(namespaces, fn
        {namespace, elements} when is_binary(namespace) and namespace != "" and is_map(elements) ->
          Enum.each(elements, fn
            {element_id, _value} when is_binary(element_id) and element_id != "" -> :ok
            _other -> raise ArgumentError, "namespace element identifiers must be non-empty strings"
          end)

        _other ->
          raise ArgumentError, "namespaces must map non-empty string names to element maps"
      end)

      namespaces
    end

    defp validate_namespaces!(_namespaces), do: raise(ArgumentError, ":namespaces must be a map")

    defp validate_validity!(%{signed: signed, valid_from: valid_from, valid_until: valid_until})
         when is_integer(signed) and is_integer(valid_from) and is_integer(valid_until) and valid_from <= valid_until do
      %{signed: signed, valid_from: valid_from, valid_until: valid_until}
    end

    defp validate_validity!(_validity) do
      raise ArgumentError, ":validity must contain integer :signed, :valid_from, and :valid_until values"
    end

    defp tagged_datetime(unix_seconds) do
      iso8601 = unix_seconds |> DateTime.from_unix!(:second) |> DateTime.to_iso8601()
      %CBOR.Tag{tag: 0, value: iso8601}
    end

    defp embedded_cbor(value), do: %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(value))}

    defp embedded_bytes(%CBOR.Tag{tag: 24, value: value}), do: byte_string(value)
    defp embedded_bytes(_value), do: {:error, :invalid_mdoc}

    defp decode_complete!(encoded) do
      case decode_complete(encoded) do
        {:ok, value} -> value
        {:error, reason} -> raise ArgumentError, "invalid CBOR: #{inspect(reason)}"
      end
    end

    defp decode_complete(encoded) when is_binary(encoded) do
      case CBOR.decode(encoded) do
        {:ok, value, ""} -> {:ok, value}
        _other -> {:error, :invalid_mdoc}
      end
    rescue
      _error -> {:error, :invalid_mdoc}
    catch
      _kind, _reason -> {:error, :invalid_mdoc}
    end

    defp decode_complete(_encoded), do: {:error, :invalid_mdoc}

    defp bytes(value) when is_binary(value), do: %CBOR.Tag{tag: :bytes, value: value}

    defp byte_string(%CBOR.Tag{tag: :bytes, value: value}) when is_binary(value), do: {:ok, value}
    defp byte_string(_other), do: {:error, :invalid_mdoc}
  end
else
  defmodule Attesto.Mdoc do
    @moduledoc "Requires the optional `:cbor` dependency."

    @dep_error "Attesto.Mdoc requires the optional :cbor dependency. " <>
                 "Add {:cbor, \"~> 1.0\"} to your deps."

    def issue(_opts), do: raise(@dep_error)
    def verify(_input, _trusted, _opts \\ []), do: raise(@dep_error)
    def verify_device_response(_device_response, _context, _trusted, _opts \\ []), do: raise(@dep_error)
    def peek_doc_type(_device_response), do: raise(@dep_error)
  end
end
