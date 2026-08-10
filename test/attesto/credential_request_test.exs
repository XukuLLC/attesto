defmodule Attesto.CredentialRequestTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.CredentialRequest

  @configuration_id "identity"
  @credential_identifier "credential-123"
  @jwt "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"

  defp request(extra \\ %{}) do
    Map.merge(%{"credential_configuration_id" => @configuration_id}, extra)
  end

  test "parses a single jwt proof with a credential configuration ID" do
    result =
      CredentialRequest.parse(
        request(%{
          "proof" => %{"proof_type" => "jwt", "jwt" => @jwt}
        })
      )

    assert result ==
             {:ok,
              %{
                selector: {:configuration_id, @configuration_id},
                proofs: [{"jwt", @jwt}],
                response_encryption: nil
              }}
  end

  test "flattens batch proofs and preserves order within each proof type" do
    assert {:ok, parsed} =
             CredentialRequest.parse(request(%{"proofs" => %{"jwt" => ["j1", "j2"]}}))

    assert parsed.proofs == [{"jwt", "j1"}, {"jwt", "j2"}]
  end

  test "rejects a proofs batch that exceeds the default cap" do
    jwts = for n <- 1..51, do: "j#{n}"

    assert {:error, :too_many_proofs} =
             CredentialRequest.parse(request(%{"proofs" => %{"jwt" => jwts}}))
  end

  test "accepts a proofs batch at exactly the default cap" do
    jwts = for n <- 1..50, do: "j#{n}"

    assert {:ok, parsed} = CredentialRequest.parse(request(%{"proofs" => %{"jwt" => jwts}}))
    assert length(parsed.proofs) == 50
  end

  test "honors a caller-supplied :max_proofs bound" do
    jwts = for n <- 1..5, do: "j#{n}"

    assert {:error, :too_many_proofs} =
             CredentialRequest.parse(request(%{"proofs" => %{"jwt" => jwts}}), max_proofs: 4)

    assert {:ok, _parsed} =
             CredentialRequest.parse(request(%{"proofs" => %{"jwt" => jwts}}), max_proofs: 5)
  end

  test "rejects a non-integer :max_proofs instead of silently disabling the cap" do
    over = for n <- 1..51, do: "j#{n}"

    # A cross-type Erlang comparison (length <= max) would treat these as
    # "unbounded" and let the batch through; validation must raise instead.
    for bad <- ["50", nil, :infinity, %{}, 5.0, -1] do
      assert_raise ArgumentError, fn ->
        CredentialRequest.parse(request(%{"proofs" => %{"jwt" => over}}), max_proofs: bad)
      end
    end
  end

  test "parses a credential identifier selector" do
    assert {:ok, parsed} =
             CredentialRequest.parse(%{
               "credential_identifier" => @credential_identifier
             })

    assert parsed.selector == {:credential_identifier, @credential_identifier}
    assert parsed.proofs == []
    assert parsed.response_encryption == nil
  end

  test "rejects both selectors and a missing selector" do
    assert {:error, :ambiguous_credential_selector} =
             CredentialRequest.parse(request(%{"credential_identifier" => @credential_identifier}))

    assert {:error, :missing_credential_selector} = CredentialRequest.parse(%{})
  end

  test "rejects both proof forms" do
    assert {:error, :ambiguous_proof} =
             CredentialRequest.parse(
               request(%{
                 "proof" => %{"proof_type" => "jwt", "jwt" => @jwt},
                 "proofs" => %{"jwt" => [@jwt]}
               })
             )
  end

  test "rejects an empty batch proof list" do
    assert {:error, :empty_proofs} =
             CredentialRequest.parse(request(%{"proofs" => %{"jwt" => []}}))
  end

  test "rejects a jwt proof with a missing or empty jwt member" do
    for proof <- [%{"proof_type" => "jwt"}, %{"proof_type" => "jwt", "jwt" => ""}] do
      assert {:error, :invalid_jwt_proof} = CredentialRequest.parse(request(%{"proof" => proof}))
    end
  end

  test "proofs are optional at parse time" do
    assert {:ok, parsed} = CredentialRequest.parse(request())
    assert parsed.proofs == []
  end

  test "normalizes valid credential response encryption parameters" do
    encryption = %{
      jwk: %{kty: "EC", crv: "P-256"},
      alg: "ECDH-ES",
      enc: "A256GCM"
    }

    assert {:ok, parsed} = CredentialRequest.parse(request(%{credential_response_encryption: encryption}))

    assert parsed.response_encryption == %{
             "jwk" => %{"kty" => "EC", "crv" => "P-256"},
             "alg" => "ECDH-ES",
             "enc" => "A256GCM"
           }
  end

  test "rejects invalid credential response encryption parameters" do
    invalid_values = [
      nil,
      %{},
      %{jwk: %{}, enc: "A256GCM"},
      %{jwk: %{}, alg: "ECDH-ES"},
      %{alg: "ECDH-ES", enc: "A256GCM"},
      %{jwk: [], alg: "ECDH-ES", enc: "A256GCM"},
      %{jwk: %{}, alg: "", enc: "A256GCM"},
      %{jwk: %{}, alg: "ECDH-ES", enc: ""}
    ]

    for encryption <- invalid_values do
      assert {:error, :invalid_credential_response_encryption} =
               CredentialRequest.parse(request(%{credential_response_encryption: encryption}))
    end
  end

  test "atom-keyed and string-keyed requests parse identically" do
    atom_keyed = %{
      credential_configuration_id: @configuration_id,
      proof: %{proof_type: "jwt", jwt: @jwt},
      credential_response_encryption: %{
        jwk: %{kty: "EC", crv: "P-256"},
        alg: "ECDH-ES",
        enc: "A256GCM"
      }
    }

    string_keyed = %{
      "credential_configuration_id" => @configuration_id,
      "proof" => %{"proof_type" => "jwt", "jwt" => @jwt},
      "credential_response_encryption" => %{
        "jwk" => %{"kty" => "EC", "crv" => "P-256"},
        "alg" => "ECDH-ES",
        "enc" => "A256GCM"
      }
    }

    assert CredentialRequest.parse(atom_keyed) == CredentialRequest.parse(string_keyed)
  end

  test "non-map input raises ArgumentError" do
    assert_raise ArgumentError, ~r/parse\/1 expects a map/, fn -> CredentialRequest.parse([]) end
  end
end
