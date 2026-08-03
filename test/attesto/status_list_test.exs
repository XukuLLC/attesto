defmodule Attesto.StatusListTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Bitwise

  alias __MODULE__.TestKeystore
  alias Attesto.{JWS, Key, StatusList}
  alias Attesto.Test.Factory

  @uri "https://issuer.example/status/1"

  setup do
    pem = Factory.ec_pem()
    TestKeystore.install(pem)

    {_kty, public_jwk} = pem |> Key.jwk() |> JOSE.JWK.to_public_map()

    public_jwk =
      Map.merge(public_jwk, %{
        "alg" => "ES256",
        "kid" => Key.kid(pem)
      })

    %{jwks: %{"keys" => [public_jwk]}}
  end

  describe "pack/2 and status_at/3" do
    test "round-trip values for every supported width across byte boundaries" do
      for bits <- [1, 2, 4, 8] do
        maximum = 1 <<< bits
        statuses = Enum.map(0..19, &rem(&1 * 3 + 1, maximum))
        packed = StatusList.pack(statuses, bits)
        per_byte = div(8, bits)

        for idx <- Enum.uniq([0, per_byte - 1, per_byte, per_byte * 2 - 1, 19]) do
          assert StatusList.status_at(packed, bits, idx) == Enum.at(statuses, idx)
        end
      end
    end

    test "packs fields least-significant first" do
      assert StatusList.pack([1, 0, 1, 0, 0, 0, 0, 1], 1) == <<0x85>>
      assert StatusList.pack([3, 2, 1, 0], 2) == <<0x1B>>
      assert StatusList.pack([15, 1], 4) == <<0x1F>>
      assert StatusList.pack([0xAB], 8) == <<0xAB>>
    end

    test "rejects unsupported widths and values that do not fit" do
      for bits <- [0, 3, 16] do
        assert_raise ArgumentError, fn -> StatusList.pack([0], bits) end
      end

      for bits <- [1, 2, 4, 8] do
        assert_raise ArgumentError, fn -> StatusList.pack([1 <<< bits], bits) end
      end

      assert_raise ArgumentError, fn -> StatusList.pack([-1], 1) end
      assert_raise ArgumentError, fn -> StatusList.status_at(<<0>>, 1, 8) end
    end
  end

  describe "issue/4 and verify/3" do
    test "preserves the subject, width, optional claims, and status values", %{jwks: jwks} do
      statuses = [0, 1, 2, 3, 1, 0, 3, 2, 1]
      now = 1_700_000_000

      token =
        StatusList.issue(TestKeystore, @uri, statuses,
          bits: 2,
          now: now,
          exp: now + 300,
          ttl: 60
        )

      assert %{"typ" => "statuslist+jwt"} = token |> JOSE.JWS.peek_protected() |> JSON.decode!()

      assert {:ok, verified} = StatusList.verify(token, jwks, accepted_algs: ["ES256"])
      assert verified.sub == @uri
      assert verified.bits == 2
      assert verified.claims["iat"] == now
      assert verified.claims["exp"] == now + 300
      assert verified.claims["ttl"] == 60

      for idx <- [0, 3, 4, 7, 8] do
        assert StatusList.status_at(verified.statuses_binary, verified.bits, idx) == Enum.at(statuses, idx)
      end
    end

    test "rejects a tampered signature", %{jwks: jwks} do
      token = StatusList.issue(TestKeystore, @uri, [0, 1, 0], now: 1_700_000_000)

      assert {:error, :invalid_signature} = StatusList.verify(tamper_signature(token), jwks)
    end

    test "rejects the wrong explicit type", %{jwks: jwks} do
      claims = valid_claims([0, 1])
      token = JWS.sign_current(TestKeystore, claims, typ: "JWT")

      assert {:error, :invalid_typ} = StatusList.verify(token, jwks)
    end

    test "rejects a missing or malformed status_list claim", %{jwks: jwks} do
      missing =
        StatusList.sign(TestKeystore, %{
          "sub" => @uri,
          "iat" => 1_700_000_000
        })

      malformed =
        StatusList.sign(TestKeystore, %{
          "sub" => @uri,
          "iat" => 1_700_000_000,
          "status_list" => %{"bits" => 1, "lst" => JWS.encode64("not zlib data")}
        })

      assert {:error, :invalid_status_list} = StatusList.verify(missing, jwks)
      assert {:error, :invalid_status_list} = StatusList.verify(malformed, jwks)
    end
  end

  describe "reference/2 and resolve/4" do
    test "builds the reference claim and resolves its status", %{jwks: jwks} do
      token = StatusList.issue(TestKeystore, @uri, [0, 2, 1, 3], bits: 2, now: 1_700_000_000)
      reference = StatusList.reference(@uri, 2)

      assert reference == %{"status_list" => %{"idx" => 2, "uri" => @uri}}

      resolver = fn uri ->
        assert uri == @uri
        {:ok, token}
      end

      assert {:ok, 1} = StatusList.resolve(reference, resolver, jwks)
      assert {:ok, 1} = StatusList.resolve(reference, resolver, fn @uri -> {:ok, jwks} end)
    end

    test "propagates a resolver error", %{jwks: jwks} do
      resolver = fn @uri -> {:error, :status_service_unavailable} end

      assert {:error, :status_service_unavailable} =
               StatusList.resolve(StatusList.reference(@uri, 0), resolver, jwks)
    end
  end

  test "handles a compressed 10,000-entry one-bit list", %{jwks: jwks} do
    revoked = MapSet.new([7, 255, 4_096, 9_999])
    statuses = Enum.map(0..9_999, &if(MapSet.member?(revoked, &1), do: 1, else: 0))
    token = StatusList.issue(TestKeystore, @uri, statuses, now: 1_700_000_000)

    assert {:ok, %{bits: 1, statuses_binary: packed}} = StatusList.verify(token, jwks)
    assert byte_size(packed) == 1_250

    for idx <- 0..9_999 do
      expected = if MapSet.member?(revoked, idx), do: 1, else: 0
      assert StatusList.status_at(packed, 1, idx) == expected
    end
  end

  defp valid_claims(statuses) do
    %{
      "sub" => @uri,
      "iat" => 1_700_000_000,
      "status_list" => StatusList.build(statuses)
    }
  end

  defp tamper_signature(token) do
    [protected, payload, signature] = String.split(token, ".")
    <<first, rest::binary>> = signature
    replacement = if first == ?A, do: ?B, else: ?A
    Enum.join([protected, payload, <<replacement, rest::binary>>], ".")
  end

  defmodule TestKeystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    def install(pem), do: Process.put({__MODULE__, :pem}, pem)

    @impl true
    def signing_pem, do: Process.get({__MODULE__, :pem})

    @impl true
    def verification_pems, do: [signing_pem()]
  end
end
