defmodule Attesto.MTLS do
  @moduledoc """
  RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and
  Certificate-Bound Access Tokens.

  A protected resource that supports mTLS-bound access tokens MUST verify
  that the access token's confirmation claim (RFC 7800 `cnf.x5t#S256`)
  matches the SHA-256 thumbprint of the client certificate presented in
  the same TLS connection. This module computes that thumbprint and
  recognises the binding shape.

  ## Thumbprint definition

  Per RFC 8705 §3.1 the `x5t#S256` value is

      base64url(SHA-256(DER-encoded certificate)), no padding

  which is the canonical shape validated by `Attesto.Thumbprint`.

  ## Why we round-trip through `:public_key.pkix_decode_cert/2`

  `compute_thumbprint/1` only digests its input after confirming that the
  bytes parse as an X.509 certificate. A caller that fed in a random
  binary would otherwise produce a "thumbprint" that no real client
  certificate could ever match - silently turning the binding into a
  permanent reject, or (if the binary came from an unauthenticated
  source) into an attacker-controlled match. Fail closed at the source.

  This module is framework-agnostic: no Plug, no database, no application
  config. It is a pure function of the certificate bytes. A resource
  server composes `Attesto.Token.verify/3` with `compute_thumbprint/1`
  applied to the DER bytes its TLS layer surfaces (e.g.
  `:ssl.peercert/1`).

  ## Where the binding may be *issued*

  Whether the listener is even allowed to issue mTLS-bound tokens (the
  TLS layer is directly terminated and the peer certificate is genuinely
  the client's, rather than a reverse-proxy socket) is a deployment fact
  the **host application** owns. Attesto does not read it from config;
  the caller decides whether to pass an mTLS thumbprint to
  `Attesto.Token.mint/2` at all.
  """

  alias Attesto.{SecureCompare, Thumbprint}

  require Record

  @public_key_records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:otp_certificate, :OTPCertificate, @public_key_records[:OTPCertificate])
  Record.defrecordp(:otp_tbs_certificate, :OTPTBSCertificate, @public_key_records[:OTPTBSCertificate])
  Record.defrecordp(:extension, :Extension, @public_key_records[:Extension])

  @subject_alt_name_oid {2, 5, 29, 17}
  @max_certificate_bytes 1_048_576
  @max_registered_identity_bytes 4_096
  @pki_metadata_fields [
    {"tls_client_auth_subject_dn", :tls_client_auth_subject_dn},
    {"tls_client_auth_san_dns", :tls_client_auth_san_dns},
    {"tls_client_auth_san_uri", :tls_client_auth_san_uri},
    {"tls_client_auth_san_ip", :tls_client_auth_san_ip},
    {"tls_client_auth_san_email", :tls_client_auth_san_email}
  ]
  @dn_oids %{
    "CN" => {2, 5, 4, 3},
    "L" => {2, 5, 4, 7},
    "ST" => {2, 5, 4, 8},
    "O" => {2, 5, 4, 10},
    "OU" => {2, 5, 4, 11},
    "C" => {2, 5, 4, 6},
    "STREET" => {2, 5, 4, 9},
    "DC" => {0, 9, 2342, 19_200_300, 100, 1, 25},
    "UID" => {0, 9, 2342, 19_200_300, 100, 1, 1},
    "EMAILADDRESS" => {1, 2, 840, 113_549, 1, 9, 1}
  }
  @oid_names Map.new(@dn_oids, fn {name, oid} -> {oid, name} end)

  @type thumbprint :: String.t()
  @type client_auth_method :: :tls_client_auth | :self_signed_tls_client_auth
  @type certificate_identities :: %{
          subject_dn: String.t(),
          san_dns: [String.t()],
          san_uri: [String.t()],
          san_ip: [String.t()],
          san_email: [String.t()]
        }

  @doc """
  Authenticate an OAuth client certificate according to RFC 8705 §2.

  For `tls_client_auth`, `client_metadata` must contain exactly one of the five
  RFC 8705 §2.1.2 subject metadata values. Attesto parses and compares that
  identity; the caller remains responsible for proving possession during the
  TLS handshake and validating the PKI chain, validity period, and revocation.

  For `self_signed_tls_client_auth`, `client_metadata` supplies a resolved
  `jwks`/`"jwks"` value. The presented DER certificate must exactly match the
  leaf certificate in an `x5c` member registered for the client. A `jwks_uri`
  is deliberately not fetched here; network resolution remains host-owned.
  """
  @spec authenticate_client(binary(), client_auth_method() | String.t(), map()) ::
          :ok | {:error, :invalid_certificate | :invalid_client_metadata | :certificate_mismatch}
  def authenticate_client(der, method, client_metadata)

  def authenticate_client(der, method, client_metadata)
      when is_binary(der) and method in [:tls_client_auth, "tls_client_auth"] and is_map(client_metadata) do
    with {:ok, parsed} <- parse_certificate(der),
         {:ok, field, expected} <- pki_identity(client_metadata),
         true <- pki_identity_matches?(parsed, field, expected) do
      :ok
    else
      {:error, _reason} = error -> error
      false -> {:error, :certificate_mismatch}
    end
  end

  def authenticate_client(der, method, client_metadata)
      when is_binary(der) and method in [:self_signed_tls_client_auth, "self_signed_tls_client_auth"] and
             is_map(client_metadata) do
    with {:ok, _parsed} <- parse_certificate(der),
         {:ok, jwks} <- resolved_client_jwks(client_metadata),
         true <- registered_certificate?(der, jwks) do
      :ok
    else
      {:error, _reason} = error -> error
      false -> {:error, :certificate_mismatch}
    end
  end

  def authenticate_client(_der, _method, _client_metadata), do: {:error, :invalid_client_metadata}

  @doc """
  Parse the RFC 8705 client identity values from a DER certificate.

  This is a syntax operation only. A successful result says nothing about the
  certificate's chain, validity, revocation status, or whether the peer proved
  possession of its private key.
  """
  @spec certificate_identities(binary()) ::
          {:ok, certificate_identities()} | {:error, :invalid_certificate}
  def certificate_identities(der) when is_binary(der) do
    with {:ok, parsed} <- parse_certificate(der) do
      {:ok, Map.delete(parsed, :subject)}
    end
  end

  def certificate_identities(_der), do: {:error, :invalid_certificate}

  @doc """
  Compute the RFC 8705 §3.1 `x5t#S256` thumbprint of an X.509 client
  certificate from its DER encoding.

  Returns `{:ok, thumbprint}` if the bytes parse as a certificate;
  `{:error, :invalid_certificate}` otherwise. The certificate is NOT
  validated against any trust store, expiry, or revocation status - that
  is the TLS terminator's responsibility. This function only ensures the
  bytes ARE a certificate (so we never emit a thumbprint for arbitrary
  attacker-controlled bytes) and computes the digest.
  """
  @spec compute_thumbprint(binary()) :: {:ok, thumbprint()} | {:error, :invalid_certificate}
  def compute_thumbprint(der) when is_binary(der) and byte_size(der) > 0 do
    if parseable_cert?(der) do
      {:ok, Thumbprint.of(der)}
    else
      {:error, :invalid_certificate}
    end
  end

  def compute_thumbprint(_), do: {:error, :invalid_certificate}

  @doc """
  Returns `true` iff `value` is a syntactically-valid `x5t#S256`
  thumbprint: the canonical base64url-no-pad encoding of a 32-byte
  SHA-256 digest. Delegates to `Attesto.Thumbprint.valid?/1`.
  """
  @spec thumbprint_shape?(term()) :: boolean()
  def thumbprint_shape?(value), do: Thumbprint.valid?(value)

  @doc """
  Returns `true` iff the given access-token claims map advertises an
  mTLS binding via the RFC 8705 `cnf.x5t#S256` confirmation claim.
  Tolerates any non-empty string value (full shape validation happens in
  `Attesto.Token.verify/3`).
  """
  @spec mtls_bound?(map()) :: boolean()
  def mtls_bound?(%{"cnf" => %{"x5t#S256" => t}}) when is_binary(t) and t != "", do: true
  def mtls_bound?(_), do: false

  @doc """
  The expected length, in characters, of a well-formed `x5t#S256`
  thumbprint.
  """
  @spec thumbprint_length() :: pos_integer()
  def thumbprint_length, do: Thumbprint.length()

  defp parse_certificate(der) do
    if byte_size(der) <= @max_certificate_bytes do
      cert = :public_key.pkix_decode_cert(der, :otp)
      tbs = otp_certificate(cert, :tbsCertificate)
      subject = otp_tbs_certificate(tbs, :subject)
      extensions = otp_tbs_certificate(tbs, :extensions)
      sans = subject_alt_names(extensions)

      {:ok,
       %{
         subject: normalize_certificate_dn(subject),
         subject_dn: encode_subject_dn(subject),
         san_dns: general_names(sans, :dNSName, &normalize_dns/1),
         san_uri: general_names(sans, :uniformResourceIdentifier, &to_utf8/1),
         san_ip: general_names(sans, :iPAddress, &format_ip/1),
         san_email: general_names(sans, :rfc822Name, &normalize_email/1)
       }}
    else
      {:error, :invalid_certificate}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  catch
    _, _ -> {:error, :invalid_certificate}
  end

  defp pki_identity(metadata) do
    configured =
      Enum.flat_map(@pki_metadata_fields, fn {string_field, atom_field} ->
        metadata
        |> Map.get(string_field, Map.get(metadata, atom_field))
        |> registered_identity(string_field)
      end)

    case configured do
      [{field, value}] -> {:ok, field, value}
      _other -> {:error, :invalid_client_metadata}
    end
  end

  defp registered_identity(nil, _field), do: []

  defp registered_identity(value, field)
       when is_binary(value) and value != "" and byte_size(value) <= @max_registered_identity_bytes do
    if String.valid?(value), do: [{field, value}], else: [:invalid]
  end

  defp registered_identity(_value, _field), do: [:invalid]

  defp pki_identity_matches?(parsed, "tls_client_auth_subject_dn", expected) do
    case parse_rfc4514_dn(expected) do
      {:ok, normalized} -> normalized == parsed.subject
      {:error, _reason} -> false
    end
  end

  defp pki_identity_matches?(parsed, "tls_client_auth_san_dns", expected), do: normalize_dns(expected) in parsed.san_dns

  defp pki_identity_matches?(parsed, "tls_client_auth_san_uri", expected), do: expected in parsed.san_uri

  defp pki_identity_matches?(parsed, "tls_client_auth_san_ip", expected) do
    expected
    |> String.to_charlist()
    |> :inet.parse_address()
    |> case do
      {:ok, address} -> (address |> :inet.ntoa() |> List.to_string()) in parsed.san_ip
      _ -> false
    end
  end

  defp pki_identity_matches?(parsed, "tls_client_auth_san_email", expected),
    do: normalize_email(expected) in parsed.san_email

  defp resolved_client_jwks(metadata) do
    case Map.get(metadata, "jwks", Map.get(metadata, :jwks)) do
      %{"keys" => keys} = jwks when is_list(keys) -> {:ok, jwks}
      %{keys: keys} = jwks when is_list(keys) -> {:ok, jwks}
      keys when is_list(keys) -> {:ok, %{"keys" => keys}}
      _other -> {:error, :invalid_client_metadata}
    end
  end

  defp registered_certificate?(der, jwks) do
    jwks
    |> Map.get("keys", Map.get(jwks, :keys, []))
    |> Enum.any?(fn key ->
      case registered_leaf_der(key) do
        {:ok, registered_der} -> SecureCompare.equal?(der, registered_der)
        :error -> false
      end
    end)
  end

  defp registered_leaf_der(key) when is_map(key) do
    case Map.get(key, "x5c", Map.get(key, :x5c)) do
      [leaf | _rest] when is_binary(leaf) -> Base.decode64(leaf)
      _other -> :error
    end
  end

  defp registered_leaf_der(_key), do: :error

  defp subject_alt_names(:asn1_NOVALUE), do: []

  defp subject_alt_names(extensions) when is_list(extensions) do
    Enum.find_value(extensions, [], fn ext ->
      if extension(ext, :extnID) == @subject_alt_name_oid, do: extension(ext, :extnValue)
    end)
  end

  defp general_names(names, type, normalize) when is_list(names) do
    names
    |> Enum.flat_map(fn
      {^type, value} -> [normalize.(value)]
      _other -> []
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp normalize_dns(value), do: value |> to_utf8() |> String.downcase()
  # RFC 5280 rfc822Name carries an SMTP mailbox. Its domain is
  # case-insensitive, but the local part is case-preserving and may be
  # case-sensitive. Lowercasing the whole mailbox would let a registration for
  # `Admin@example.com` authenticate a certificate for `admin@example.com`.
  defp normalize_email(value) do
    value
    |> to_utf8()
    |> normalize_mailbox_domain()
  end

  defp normalize_mailbox_domain(mailbox) do
    case :binary.matches(mailbox, "@") do
      [] -> mailbox
      matches -> lowercase_mailbox_domain(mailbox, matches |> List.last() |> elem(0))
    end
  end

  defp lowercase_mailbox_domain(mailbox, at_offset) do
    local = binary_part(mailbox, 0, at_offset + 1)
    domain = binary_part(mailbox, at_offset + 1, byte_size(mailbox) - at_offset - 1)
    local <> String.downcase(domain)
  end

  defp format_ip(bytes) when is_binary(bytes) and byte_size(bytes) in [4, 16] do
    bytes
    |> ip_tuple()
    |> :inet.ntoa()
    |> List.to_string()
  end

  defp format_ip(_bytes), do: nil

  defp ip_tuple(<<a, b, c, d>>), do: {a, b, c, d}

  defp ip_tuple(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>), do: {a, b, c, d, e, f, g, h}

  defp encode_subject_dn({:rdnSequence, rdns}) do
    rdns
    |> Enum.reverse()
    |> Enum.map_join(",", fn rdn ->
      rdn
      |> Enum.map_join("+", fn {:AttributeTypeAndValue, oid, value} ->
        "#{Map.get(@oid_names, oid, oid_string(oid))}=#{escape_dn_value(attribute_value(value))}"
      end)
    end)
  end

  defp normalize_certificate_dn({:rdnSequence, rdns}) do
    Enum.map(rdns, fn rdn ->
      rdn
      |> Enum.map(fn {:AttributeTypeAndValue, oid, value} -> {oid, normalize_dn_value(attribute_value(value))} end)
      |> Enum.sort()
    end)
  end

  defp parse_rfc4514_dn(value) do
    with {:ok, rdns} <- split_unescaped(value, ?,),
         {:ok, parsed} <- map_ok(rdns, &parse_rdn/1) do
      {:ok, Enum.reverse(parsed)}
    end
  end

  defp parse_rdn(value) do
    with {:ok, attributes} <- split_unescaped(value, ?+),
         {:ok, parsed} <- map_ok(attributes, &parse_dn_attribute/1) do
      {:ok, Enum.sort(parsed)}
    end
  end

  defp parse_dn_attribute(value) do
    with {:ok, [type, encoded_value]} <- split_first_unescaped(value, ?=),
         {:ok, oid} <- parse_dn_type(type),
         {:ok, decoded_value} <- unescape_dn_value(encoded_value) do
      {:ok, {oid, normalize_dn_value(decoded_value)}}
    else
      _other -> {:error, :invalid_dn}
    end
  end

  defp parse_dn_type(type) do
    normalized = type |> String.trim() |> String.upcase()

    case Map.fetch(@dn_oids, normalized) do
      {:ok, oid} -> {:ok, oid}
      :error -> parse_numeric_oid(normalized)
    end
  end

  defp parse_numeric_oid("OID." <> value), do: parse_numeric_oid(value)

  defp parse_numeric_oid(value) do
    parts = String.split(value, ".")

    if length(parts) >= 2 do
      case parse_oid_parts(parts) do
        :error -> {:error, :invalid_dn}
        integers -> {:ok, integers |> Enum.reverse() |> List.to_tuple()}
      end
    else
      {:error, :invalid_dn}
    end
  end

  defp parse_oid_parts(parts) do
    Enum.reduce_while(parts, [], fn part, acc ->
      case Integer.parse(part) do
        {integer, ""} when integer >= 0 -> {:cont, [integer | acc]}
        _other -> {:halt, :error}
      end
    end)
  end

  defp split_unescaped(value, delimiter) when is_binary(value) do
    do_split_unescaped(value, delimiter, [], <<>>, false)
  end

  defp do_split_unescaped(<<>>, _delimiter, acc, current, false), do: {:ok, Enum.reverse([current | acc])}
  defp do_split_unescaped(<<>>, _delimiter, _acc, _current, true), do: {:error, :invalid_escape}

  defp do_split_unescaped(<<?\\, rest::binary>>, delimiter, acc, current, false),
    do: do_split_unescaped(rest, delimiter, acc, current <> <<?\\>>, true)

  defp do_split_unescaped(<<char, rest::binary>>, delimiter, acc, current, true),
    do: do_split_unescaped(rest, delimiter, acc, current <> <<char>>, false)

  defp do_split_unescaped(<<delimiter, rest::binary>>, delimiter, acc, current, false),
    do: do_split_unescaped(rest, delimiter, [current | acc], <<>>, false)

  defp do_split_unescaped(<<char, rest::binary>>, delimiter, acc, current, false),
    do: do_split_unescaped(rest, delimiter, acc, current <> <<char>>, false)

  defp split_first_unescaped(value, delimiter) do
    case split_unescaped(value, delimiter) do
      {:ok, [left, right]} -> {:ok, [left, right]}
      {:ok, [left | rest]} when rest != [] -> {:ok, [left, Enum.join(rest, <<delimiter>>)]}
      _other -> {:error, :invalid_dn}
    end
  end

  defp unescape_dn_value("#" <> _hex_der), do: {:error, :unsupported_hex_dn_value}
  defp unescape_dn_value(value), do: do_unescape_dn_value(value, <<>>)

  defp do_unescape_dn_value(<<>>, acc), do: {:ok, acc}

  defp do_unescape_dn_value(<<?\\, a, b, rest::binary>>, acc)
       when a in ~c"0123456789abcdefABCDEF" and b in ~c"0123456789abcdefABCDEF" do
    byte = String.to_integer(<<a, b>>, 16)
    do_unescape_dn_value(rest, acc <> <<byte>>)
  end

  defp do_unescape_dn_value(<<?\\, char, rest::binary>>, acc)
       when char in [?,, ?+, ?\", ?\\, ?<, ?>, ?;, ?=, ?#, ?\s] do
    do_unescape_dn_value(rest, acc <> <<char>>)
  end

  defp do_unescape_dn_value(<<?\\, _rest::binary>>, _acc), do: {:error, :invalid_escape}
  defp do_unescape_dn_value(<<char, rest::binary>>, acc), do: do_unescape_dn_value(rest, acc <> <<char>>)

  defp map_ok(values, fun) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
      case fun.(value) do
        {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, parsed} -> {:ok, Enum.reverse(parsed)}
      error -> error
    end
  end

  defp attribute_value({_type, value}), do: to_utf8(value)
  defp attribute_value(value), do: to_utf8(value)

  defp to_utf8(value) when is_binary(value), do: value
  defp to_utf8(value) when is_list(value), do: List.to_string(value)
  defp to_utf8(value), do: to_string(value)

  defp normalize_dn_value(value) do
    value
    |> String.trim()
    |> String.replace(~r/\s+/u, " ")
    |> String.downcase()
  end

  defp escape_dn_value(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace(~r/([,\+\"<>;=])/, "\\\\\\1")
    |> escape_edge_space()
    |> escape_leading_hash()
  end

  defp escape_edge_space(value) do
    value
    |> then(fn string ->
      if String.starts_with?(string, " "), do: "\\ " <> binary_part(string, 1, byte_size(string) - 1), else: string
    end)
    |> then(fn string ->
      if String.ends_with?(string, " "), do: binary_part(string, 0, byte_size(string) - 1) <> "\\ ", else: string
    end)
  end

  defp escape_leading_hash("#" <> rest), do: "\\#" <> rest
  defp escape_leading_hash(value), do: value

  defp oid_string(oid), do: oid |> Tuple.to_list() |> Enum.join(".")

  # `:public_key.pkix_decode_cert/2` raises a MatchError for any input
  # that isn't a parseable X.509 certificate (bad ASN.1, empty binary,
  # random garbage). We rescue both the `error` and `throw`/`exit` paths
  # and collapse them into a single boolean so callers cannot fingerprint
  # the parser.
  defp parseable_cert?(der) do
    if byte_size(der) <= @max_certificate_bytes do
      _ = :public_key.pkix_decode_cert(der, :plain)
      true
    else
      false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end
end
