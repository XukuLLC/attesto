defmodule Attesto.Test.X509Fixture do
  @moduledoc false

  require Record

  @records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:certificate, :OTPCertificate, @records[:OTPCertificate])
  Record.defrecordp(:tbs_certificate, :OTPTBSCertificate, @records[:OTPTBSCertificate])
  Record.defrecordp(:extension, :Extension, @records[:Extension])

  @curve {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

  def root do
    :public_key.pkix_test_root_cert(~c"synthetic-x509-root", key: @curve)
  end

  def chain(root, opts \\ []) do
    peer = Keyword.merge([key: @curve], Keyword.get(opts, :peer, []))

    data =
      :public_key.pkix_test_data(%{
        root: root,
        intermediates: Keyword.get(opts, :intermediates, []),
        peer: peer
      })

    intermediates = Enum.reject(data[:cacerts], &(&1 == root.cert))
    key = data[:key] |> elem(1) |> JOSE.JWK.from_der()

    %{
      leaf: data[:cert],
      chain: [data[:cert] | intermediates],
      key: key,
      public_key: key |> JOSE.JWK.to_public_map() |> elem(1),
      anchors: [root.cert]
    }
  end

  def named_chain(root, names, opts \\ []) do
    peer = Keyword.get(opts, :peer, [])
    extensions = [san(names) | Keyword.get(peer, :extensions, [])]
    chain(root, Keyword.put(opts, :peer, Keyword.put(peer, :extensions, extensions)))
  end

  def san(names), do: {:Extension, {2, 5, 29, 17}, false, names}
  def signer_usage, do: {:Extension, {2, 5, 29, 37}, true, [{1, 0, 18_013, 5, 1, 2}]}
  def curve, do: @curve

  def replace_extension(der, signer, oid, replacement) do
    tbs = der |> :public_key.pkix_decode_cert(:otp) |> certificate(:tbsCertificate)
    extensions = Enum.reject(tbs_certificate(tbs, :extensions), &(extension(&1, :extnID) == oid))
    extensions = if is_nil(replacement), do: extensions, else: [replacement | extensions]
    tbs |> tbs_certificate(extensions: extensions) |> :public_key.pkix_sign(signer)
  end

  def tamper(der) do
    last = byte_size(der) - 1
    binary_part(der, 0, last) <> <<Bitwise.bxor(:binary.last(der), 1)>>
  end
end
