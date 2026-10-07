defmodule Attesto.Parity.JWECryptographyParityTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.{JWE, JWS}

  @python System.get_env("ATTESTO_PYTHON") || System.find_executable("python3")
  @script Path.expand("../support/python/jwe_cryptography.py", __DIR__)
  @plaintext <<0, 255, "synthetic credential payload", 10, 0>>

  @moduletag :parity

  if is_nil(@python) do
    @moduletag skip: "Python cryptography is unavailable"
  else
    case System.cmd(@python, ["-c", "import cryptography"], stderr_to_stdout: true) do
      {_output, 0} -> :ok
      {_output, _status} -> @moduletag skip: "Python cryptography is unavailable"
    end
  end

  setup do
    directory = Path.join(System.tmp_dir!(), "attesto-jwe-parity-#{System.unique_integer([:positive])}")
    File.mkdir_p!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)

    private = JOSE.JWK.generate_key({:ec, "P-256"})
    {_modules, private_map} = JOSE.JWK.to_map(private)
    {_modules, public} = JOSE.JWK.to_public_map(private)
    {:ok, directory: directory, private: private, private_map: private_map, public: public}
  end

  for enc <- ~w(A128GCM A256GCM), party_info? <- [false, true] do
    @enc enc
    @party_info? party_info?

    test "Attesto to Python #{@enc}, party info #{@party_info?}", context do
      header = header(@enc, @party_info?)
      assert {:ok, compact} = JWE.encrypt(context.public, @plaintext, header)

      result =
        python(context.directory, %{
          "operation" => "decrypt",
          "key" => context.private_map,
          "compact" => compact
        })

      assert result["plaintext"] == JWS.encode64(@plaintext)
      assert Map.take(result["header"], Map.keys(header)) == header
      refute Map.has_key?(result["header"]["epk"], "d")
    end

    test "Python to Attesto #{@enc}, party info #{@party_info?}", context do
      header = header(@enc, @party_info?)

      result =
        python(context.directory, %{
          "operation" => "encrypt",
          "key" => context.public,
          "plaintext" => JWS.encode64(@plaintext),
          "header" => header
        })

      assert {:ok, @plaintext, recovered_header} = JWE.decrypt(context.private, result["compact"])
      assert recovered_header == result["header"]
      assert Map.take(recovered_header, Map.keys(header)) == header
    end
  end

  defp header(enc, false), do: %{"alg" => "ECDH-ES", "enc" => enc, "kid" => "synthetic-recipient"}

  defp header(enc, true) do
    Map.merge(header(enc, false), %{
      "apu" => JWS.encode64(<<0, "wallet", 255>>),
      "apv" => JWS.encode64(<<255, "verifier nonce", 0>>)
    })
  end

  defp python(directory, request) do
    input = Path.join(directory, "request.json")
    File.write!(input, JSON.encode!(request))
    File.chmod!(input, 0o600)
    {output, status} = System.cmd(@python, [@script, input], stderr_to_stdout: true)
    assert status == 0, "Independent Python cryptography fixture failed: #{output}"
    JSON.decode!(output)
  end
end
