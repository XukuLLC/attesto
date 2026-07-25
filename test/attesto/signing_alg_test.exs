defmodule Attesto.SigningAlgTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.SigningAlg

  test "deprecated keyless EdDSA helpers return the Ed25519 profile" do
    hash_alg = Function.capture(SigningAlg, :hash_alg, 1)
    hash_half_bytes = Function.capture(SigningAlg, :hash_half_bytes, 1)

    assert hash_alg.("EdDSA") == :sha512
    assert hash_half_bytes.("EdDSA") == 32
    assert hash_alg.("Ed25519") == :sha512
    assert hash_half_bytes.("Ed25519") == 32

    assert_raise ArgumentError, ~r/Ed448 uses SHAKE256/, fn -> hash_alg.("Ed448") end
    assert_raise ArgumentError, ~r/Ed448 uses SHAKE256/, fn -> hash_half_bytes.("Ed448") end
  end

  test "legacy and RFC 9864 profiles distinguish Ed25519 fixed hashing from Ed448 XOF hashing" do
    assert SigningAlg.oidc_hash_profile("EdDSA", ed25519_jwk()) == {:fixed, :sha512, 32}
    assert SigningAlg.oidc_hash_profile("EdDSA", ed448_jwk()) == {:xof, :shake256, 114, 57}
    assert SigningAlg.oidc_hash_profile("Ed25519", ed25519_jwk()) == {:fixed, :sha512, 32}
    assert SigningAlg.oidc_hash_profile("Ed448", ed448_jwk()) == {:xof, :shake256, 114, 57}
  end

  test "an Ed448 OIDC hash claim contains the left-most 57 bytes" do
    previous = JOSE.sha3_module()
    JOSE.sha3_module(:jose_jwa_sha3)
    on_exit(fn -> JOSE.sha3_module(previous) end)

    encoded = SigningAlg.oidc_hash("ed448-hash-length", "EdDSA", ed448_jwk())
    assert {:ok, decoded} = Base.url_decode64(encoded, padding: false)
    assert byte_size(decoded) == 57
  end

  test "EdDSA profiles reject a non-OKP key and an unsupported OKP curve" do
    for jwk <- [JOSE.JWK.generate_key({:ec, "P-256"}), x25519_jwk()] do
      assert_raise ArgumentError, ~r/not compatible with trusted key/, fn ->
        SigningAlg.oidc_hash_profile("EdDSA", jwk)
      end
    end
  end

  test "explicit identifiers reject the other Edwards curve" do
    assert_raise ArgumentError, ~r/"Ed25519" is not compatible/, fn ->
      SigningAlg.validate_for_key!("Ed25519", ed448_jwk())
    end

    assert_raise ArgumentError, ~r/"Ed448" is not compatible/, fn ->
      SigningAlg.validate_for_key!("Ed448", ed25519_jwk())
    end
  end

  test "the default FAPI policy accepts only the Ed25519 curve" do
    assert SigningAlg.fapi_compatible?("EdDSA", ed25519_jwk())
    assert SigningAlg.fapi_compatible?("Ed25519", ed25519_jwk())
    refute SigningAlg.fapi_compatible?("EdDSA", ed448_jwk())
    refute SigningAlg.fapi_compatible?("Ed448", ed448_jwk())
  end

  test "the default FAPI policy requires an RSA modulus of at least 2048 bits" do
    weak_key = JOSE.JWK.generate_key({:rsa, 1024})
    compliant_key = JOSE.JWK.generate_key({:rsa, 2048})

    refute SigningAlg.fapi_compatible?("PS256", weak_key)
    assert SigningAlg.fapi_compatible?("PS256", compliant_key)

    # Key/algorithm validation remains profile-neutral for explicit non-FAPI
    # policies that intentionally retain compatibility with a weaker key.
    assert SigningAlg.validate_for_key!("PS256", weak_key) == "PS256"
  end

  test "missing SHAKE256 support raises a clear configuration error" do
    previous = JOSE.sha3_module()
    JOSE.sha3_module(:jose_sha3_unsupported)
    on_exit(fn -> JOSE.sha3_module(previous) end)

    assert_raise ArgumentError, ~r/require a configured JOSE SHA3 backend with SHAKE256 support/, fn ->
      SigningAlg.oidc_hash("ed448-needs-shake256", "Ed448", ed448_jwk())
    end
  end

  test "Ed448 infers the curve-independent EdDSA JOSE algorithm" do
    assert SigningAlg.infer(ed448_jwk()) == "EdDSA"
  end

  test "allowed algorithms include RFC 9864 identifiers while inference remains legacy" do
    assert "Ed25519" in SigningAlg.allowed()
    assert "Ed448" in SigningAlg.allowed()
    assert "Ed25519" in SigningAlg.fapi_algs()
    refute "Ed448" in SigningAlg.fapi_algs()
    assert SigningAlg.infer(ed25519_jwk()) == "EdDSA"
    assert SigningAlg.infer(ed448_jwk()) == "EdDSA"
  end

  # A correctly sized public member is sufficient to exercise trusted curve
  # inference without requiring a configured Curve448 signing backend.
  defp ed25519_jwk, do: okp_jwk("Ed25519", 32)
  defp ed448_jwk, do: okp_jwk("Ed448", 57)
  defp x25519_jwk, do: okp_jwk("X25519", 32)

  defp okp_jwk(curve, bytes) do
    x = :binary.copy(<<1>>, bytes) |> Base.url_encode64(padding: false)
    JOSE.JWK.from_map(%{"kty" => "OKP", "crv" => curve, "x" => x})
  end
end
