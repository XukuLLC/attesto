defmodule Attesto.JWSTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias __MODULE__.{CurrentKeystore, ExternalSigner}
  alias Attesto.JWS
  alias Attesto.Key
  alias Attesto.Test.Factory

  defp public_map(key, overrides) do
    {_kty, map} = JOSE.JWK.to_public_map(key)
    Map.merge(map, overrides)
  end

  defp signed_jwt(key, kid) do
    {_, jwt} =
      key
      |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => kid}, %{"ok" => true})
      |> JOSE.JWS.compact()

    jwt
  end

  defp protected_header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  describe "sign_current/3" do
    test "derives the correct alg and kid for EC and RSA keys" do
      for {pem, alg} <- [{Factory.ec_pem(), "ES256"}, {Factory.rsa_pem(), "RS256"}] do
        CurrentKeystore.install(pem)

        jwt =
          JWS.sign_current(CurrentKeystore, %{"sub" => "user-123"},
            typ: "JWT",
            extra_protected: %{"cty" => "example"}
          )

        assert protected_header(jwt) == %{
                 "alg" => alg,
                 "kid" => Key.kid(pem),
                 "typ" => "JWT",
                 "cty" => "example"
               }

        assert {true, %JOSE.JWT{}, %JOSE.JWS{}} =
                 JOSE.JWT.verify_strict(Key.jwk(pem), [alg], jwt)

        assert CurrentKeystore.signing_pem_calls() == 1
      end
    end

    test "rejects extra protected members that collide with helper-owned fields" do
      pem = Factory.ec_pem()
      CurrentKeystore.install(pem)

      for reserved <- ["alg", "kid", "typ"] do
        assert_raise ArgumentError, fn ->
          JWS.sign_current(CurrentKeystore, %{"ok" => true}, extra_protected: Map.put(%{}, reserved, "caller-value"))
        end
      end
    end

    test "raises when the current PEM is empty or contains multiple keys" do
      multi_key_pem = Factory.rsa_pem() <> Factory.ec_pem()

      for pem <- ["", multi_key_pem] do
        CurrentKeystore.install(pem)

        assert_raise ArgumentError, fn ->
          JWS.sign_current(CurrentKeystore, %{"ok" => true})
        end

        assert CurrentKeystore.signing_pem_calls() == 1
      end
    end

    test "signs through a non-extractable Signer without reading private PEM material" do
      private_pem = Factory.rsa_pem()
      public_pem = Key.public_pem(private_pem)
      ExternalSigner.install(private_pem, public_pem)

      jwt = JWS.sign_current(ExternalSigner, %{"sub" => "hsm-backed"}, typ: "JWT")

      assert protected_header(jwt) == %{
               "alg" => "RS256",
               "kid" => Key.kid(public_pem),
               "typ" => "JWT"
             }

      assert {true, %JOSE.JWT{fields: %{"sub" => "hsm-backed"}}, %JOSE.JWS{}} =
               JOSE.JWT.verify_strict(Key.jwk(public_pem), ["RS256"], jwt)

      assert ExternalSigner.sign_calls() == 1
      refute function_exported?(ExternalSigner, :signing_pem, 0)
    end

    test "rejects an external signer that returns private key material" do
      private_jwk = JOSE.JWK.generate_key({:rsa, 2048})
      ExternalSigner.install_signing_jwk(private_jwk)

      assert_raise ArgumentError, ~r/invalid signer public JWK/, fn ->
        Attesto.Signer.signing_jwk!(ExternalSigner)
      end
    end

    test "rejects a signature produced by a different remote key" do
      signing_private = JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
      advertised_public = JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem() |> elem(1)
      ExternalSigner.install(signing_private, advertised_public)

      assert_raise RuntimeError, ~r/does not match its public JWK and alg/, fn ->
        JWS.sign_current(ExternalSigner, %{"sub" => "wrong-key"}, typ: "JWT")
      end
    end

    test "honors an external public JWK alg instead of silently falling back to key-type inference" do
      private_pem = Factory.rsa_pem()
      public_pem = Key.public_pem(private_pem)
      ExternalSigner.install(private_pem, public_pem)

      {_kind, public_map} = public_pem |> Key.jwk() |> JOSE.JWK.to_public_map()
      ExternalSigner.install_signing_jwk(Map.put(public_map, "alg", "PS256"))

      jwt = JWS.sign_current(ExternalSigner, %{"sub" => "pss-hsm"}, typ: "JWT")
      assert protected_header(jwt)["alg"] == "PS256"
      assert {true, %JOSE.JWT{}, %JOSE.JWS{}} = JOSE.JWT.verify_strict(Key.jwk(public_pem), ["PS256"], jwt)
    end

    test "rejects an external PS256 signature with a non-JOSE salt length" do
      private_pem = Factory.rsa_pem()
      public_pem = Key.public_pem(private_pem)
      ExternalSigner.install(private_pem, public_pem)
      ExternalSigner.install_pss_saltlen(222)

      {_kind, public_map} = public_pem |> Key.jwk() |> JOSE.JWK.to_public_map()
      ExternalSigner.install_signing_jwk(Map.put(public_map, "alg", "PS256"))

      assert_raise RuntimeError, ~r/does not match its public JWK and alg/, fn ->
        JWS.sign_current(ExternalSigner, %{"sub" => "bad-pss-salt"}, typ: "JWT")
      end
    end
  end

  test "keeps candidate order and narrows by kid after algorithm filtering" do
    first = JOSE.JWK.generate_key({:ec, "P-256"})
    second = JOSE.JWK.generate_key({:ec, "P-256"})
    second_kid = JOSE.JWK.thumbprint(second)

    candidates =
      JWS.verification_candidates(
        [
          public_map(first, %{"kid" => JOSE.JWK.thumbprint(first), "alg" => "ES256"}),
          public_map(second, %{"kid" => second_kid, "alg" => "ES256"})
        ],
        accepted_algs: ["ES256"],
        kid: second_kid
      )

    assert [{^second_kid, "ES256", %JOSE.JWK{}}] = candidates
  end

  test "reject_set and skip preserve their distinct malformed-key policies" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    valid = public_map(key, %{"kid" => "valid", "alg" => "ES256"})
    malformed = %{"not" => "a jwk"}

    assert JWS.verification_candidates([valid, malformed], accepted_algs: ["ES256"], malformed_key: :reject_set) ==
             []

    assert [{"valid", "ES256", %JOSE.JWK{}}] =
             JWS.verification_candidates([malformed, valid],
               accepted_algs: ["ES256"],
               malformed_key: :skip
             )
  end

  test "strict verification tries candidates in order and exposes the selected key when requested" do
    signer = JOSE.JWK.generate_key({:ec, "P-256"})
    wrong = JOSE.JWK.generate_key({:ec, "P-256"})
    signer_kid = JOSE.JWK.thumbprint(signer)
    jwt = signed_jwt(signer, signer_kid)

    candidates =
      JWS.verification_candidates(
        [
          public_map(wrong, %{"kid" => "wrong", "alg" => "ES256"}),
          public_map(signer, %{"kid" => signer_kid, "alg" => "ES256"})
        ],
        accepted_algs: ["ES256"]
      )

    assert {:ok, %{"ok" => true}, {^signer_kid, "ES256", %JOSE.JWK{}}} =
             JWS.verify_strict(jwt, candidates, return_key?: true)

    wrong_candidates =
      JWS.verification_candidates(public_map(wrong, %{"kid" => "wrong", "alg" => "ES256"}),
        accepted_algs: ["ES256"]
      )

    assert {:error, :wrong_key} = JWS.verify_strict(jwt, wrong_candidates, terminal_error: :wrong_key)
  end

  # ── parser primitives (the compact-JWS parser consolidation) ──────────────

  describe "base64url helpers" do
    test "encode64/1 and decode64/2 round-trip binary data" do
      bytes = <<0, 1, 2, 253, 254, 255>>
      encoded = JWS.encode64(bytes)

      assert {:ok, ^bytes} = JWS.decode64(encoded)
      assert encoded == "AAEC_f7_"
    end

    test "decode64/2 rejects non-canonical trailing bits" do
      assert {:error, :non_canonical_base64url} = JWS.decode64("AAB")
    end
  end

  defp b64(bytes), do: JWS.encode64(bytes)

  describe "decode_compact/2" do
    test "splits a canonical three-segment JWT" do
      jwt = "#{b64("h")}.#{b64("p")}.#{b64("s")}"
      assert {:ok, seg} = JWS.decode_compact(jwt)
      assert seg.protected_segment == b64("h")
      assert seg.payload_segment == b64("p")
      assert seg.signature_segment == b64("s")
    end

    test "rejects anything that is not exactly three segments" do
      assert {:error, :malformed_compact} = JWS.decode_compact("only.two")
      assert {:error, :malformed_compact} = JWS.decode_compact("a.b.c.d")
      assert {:error, :malformed_compact} = JWS.decode_compact("nodots")
    end

    test "rejects an empty signature by default; accepts it when allowed" do
      jwt = "#{b64("h")}.#{b64("p")}."
      assert {:error, :malformed_compact} = JWS.decode_compact(jwt)
      assert {:ok, _} = JWS.decode_compact(jwt, allow_empty_signature: true)
    end

    test "rejects a non-canonical base64url segment when canonical (the default)" do
      # "AAB" decodes to <<0, 0>> but canonically re-encodes to "AAA".
      jwt = "AAB.#{b64("p")}.#{b64("s")}"
      assert {:error, :non_canonical_base64url} = JWS.decode_compact(jwt)
    end

    test "rejects non-binary input" do
      assert {:error, :malformed_compact} = JWS.decode_compact(123)
    end
  end

  describe "peek_json/3" do
    test "decodes the protected header and the payload to maps" do
      header = %{"alg" => "ES256", "typ" => "x"}
      payload = %{"sub" => "u"}
      jwt = "#{b64(JSON.encode!(header))}.#{b64(JSON.encode!(payload))}.#{b64("s")}"

      assert {:ok, ^header} = JWS.peek_json(jwt, :protected)
      assert {:ok, ^payload} = JWS.peek_json(jwt, :payload)
    end

    test "errors on a segment that is not valid JSON" do
      jwt = "#{b64("not json")}.#{b64(JSON.encode!(%{}))}.#{b64("s")}"
      assert {:error, :invalid_json} = JWS.peek_json(jwt, :protected)
    end

    test "errors on JSON that is not an object" do
      jwt = "#{b64(JSON.encode!([1, 2]))}.#{b64(JSON.encode!(%{}))}.#{b64("s")}"
      assert {:error, :invalid_json} = JWS.peek_json(jwt, :protected)
    end

    test "peeks an alg=none header (empty signature) by default" do
      header = %{"alg" => "none"}
      jwt = "#{b64(JSON.encode!(header))}.#{b64(JSON.encode!(%{}))}."
      assert {:ok, %{"alg" => "none"}} = JWS.peek_json(jwt, :protected)
    end
  end

  describe "reject_unsupported_crit/2" do
    test "ok when there is no crit member" do
      assert :ok = JWS.reject_unsupported_crit(%{"alg" => "ES256"})
    end

    test "ok when every crit member is supported" do
      assert :ok = JWS.reject_unsupported_crit(%{"crit" => ["b64"]}, supported: ["b64"])
    end

    test "rejects an unsupported crit member" do
      assert {:error, :unsupported_crit} = JWS.reject_unsupported_crit(%{"crit" => ["b64"]})
    end

    test "rejects an empty or non-array crit" do
      assert {:error, :unsupported_crit} = JWS.reject_unsupported_crit(%{"crit" => []})
      assert {:error, :unsupported_crit} = JWS.reject_unsupported_crit(%{"crit" => "b64"})
    end
  end

  defmodule CurrentKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    def install(pem) when is_binary(pem) do
      Process.put({__MODULE__, :pem}, pem)
      Process.put({__MODULE__, :calls}, 0)
    end

    def signing_pem_calls, do: Process.get({__MODULE__, :calls}, 0)

    @impl true
    def signing_pem do
      Process.put({__MODULE__, :calls}, signing_pem_calls() + 1)
      Process.get({__MODULE__, :pem})
    end

    @impl true
    def verification_pems, do: [Process.get({__MODULE__, :pem})]
  end

  defmodule ExternalSigner do
    @moduledoc false
    @behaviour Attesto.Keystore
    @behaviour Attesto.Signer

    def install(private_pem, public_pem) do
      Process.put({__MODULE__, :private_pem}, private_pem)
      Process.put({__MODULE__, :public_pem}, public_pem)
      Process.put({__MODULE__, :sign_calls}, 0)
    end

    def sign_calls, do: Process.get({__MODULE__, :sign_calls}, 0)

    def install_signing_jwk(jwk), do: Process.put({__MODULE__, :signing_jwk}, jwk)
    def install_pss_saltlen(length), do: Process.put({__MODULE__, :pss_saltlen}, length)

    @impl Attesto.Signer
    def signing_jwk do
      case Process.get({__MODULE__, :signing_jwk}) do
        nil ->
          {_kind, public_map} = Process.get({__MODULE__, :public_pem}) |> Key.jwk() |> JOSE.JWK.to_public_map()
          public_map

        jwk ->
          jwk
      end
    end

    @impl Attesto.Signer
    def sign(signing_input, "RS256") do
      Process.put({__MODULE__, :sign_calls}, sign_calls() + 1)

      private_key =
        Process.get({__MODULE__, :private_pem})
        |> Key.signing_jwk()
        |> JOSE.JWK.to_key()
        |> elem(1)

      {:ok, :public_key.sign(signing_input, :sha256, private_key)}
    end

    def sign(signing_input, "PS256") do
      Process.put({__MODULE__, :sign_calls}, sign_calls() + 1)

      private_key =
        Process.get({__MODULE__, :private_pem})
        |> Key.signing_jwk()
        |> JOSE.JWK.to_key()
        |> elem(1)

      {:ok,
       :public_key.sign(signing_input, :sha256, private_key,
         rsa_padding: :rsa_pkcs1_pss_padding,
         rsa_pss_saltlen: Process.get({__MODULE__, :pss_saltlen}, 32)
       )}
    end

    @impl Attesto.Keystore
    def verification_pems, do: [Process.get({__MODULE__, :public_pem})]
  end
end
