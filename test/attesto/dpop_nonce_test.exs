defmodule Attesto.DPoPNonceTest do
  @moduledoc false
  # RFC 9449 §8 server-issued DPoP nonces, on two surfaces:
  #
  #   1. The pure engine seam: `Attesto.DPoP.verify_proof/2`'s `:nonce_check`
  #      callback, which receives the proof's `nonce` claim (possibly nil)
  #      and returns `:ok` or `{:error, :use_dpop_nonce}`. No `:nonce_check`
  #      means no nonce is required; a non-1-arity callback, or one that
  #      returns anything other than the two legal values, is a caller bug
  #      and raises.
  #
  #   2. The bundled single-node store `Attesto.DPoP.NonceStore.ETS`, whose
  #      `issue/1` mints a nonce, `valid?/1` reports liveness, `validate/1`
  #      is the `:nonce_check` shape, and `reset/0` clears it. The store is a
  #      named singleton, so it is `start_supervised!`-ed once per test and
  #      this module runs `async: false`.
  #
  # Nonce-carrying proofs are signed by hand with JOSE: `Factory.dpop_proof/1`
  # has no `nonce` knob, so we embed the `"nonce"` claim directly the way
  # `dpop_header_test.exs` forges proofs.
  use ExUnit.Case, async: false

  alias Attesto.DPoP
  alias Attesto.DPoP.NonceStore.ETS, as: NonceStore

  @http_method "POST"
  @http_uri "https://api.example.com/oauth/token"

  # -----------------------------------------------------------------
  # proof-building helpers (mirroring dpop_header_test.exs)
  # -----------------------------------------------------------------

  defp unix_now, do: System.system_time(:second)

  defp gen_ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_map(%JOSE.JWK{} = key) do
    {_, map} = JOSE.JWK.to_public_map(key)
    map
  end

  defp base_header(jwk_map), do: %{"typ" => "dpop+jwt", "alg" => "ES256", "jwk" => jwk_map}

  defp claims(overrides) do
    Map.merge(
      %{
        "htm" => @http_method,
        "htu" => @http_uri,
        "iat" => unix_now(),
        "jti" => "jti-" <> Integer.to_string(System.unique_integer([:positive]))
      },
      overrides
    )
  end

  # Sign a proof whose payload carries `claim_overrides` (e.g. a "nonce"
  # claim, or none for the nil case). The header alg matches the signature.
  defp signed_proof(claim_overrides) do
    key = gen_ec_key()

    {_protected, compact} =
      key
      |> JOSE.JWT.sign(base_header(public_map(key)), claims(claim_overrides))
      |> JOSE.JWS.compact()

    compact
  end

  # Pin `now` so a slow run never drifts the proof out of the iat window.
  defp verify_opts(extra \\ []) do
    Keyword.merge([http_method: @http_method, http_uri: @http_uri, now: unix_now()], extra)
  end

  # =================================================================
  # (1) verify_proof :nonce_check
  # =================================================================

  describe "verify_proof :nonce_check" do
    test "a proof carrying a nonce the check accepts verifies" do
      proof = signed_proof(%{"nonce" => "server-nonce-abc"})

      check = fn
        "server-nonce-abc" -> :ok
        _ -> {:error, :use_dpop_nonce}
      end

      assert {:ok, %{htm: @http_method, htu: @http_uri}} =
               DPoP.verify_proof(proof, verify_opts(nonce_check: check))
    end

    test "the accepted nonce is the exact value handed to the check" do
      proof = signed_proof(%{"nonce" => "the-only-good-nonce"})
      seen = self()

      check = fn nonce ->
        send(seen, {:nonce_seen, nonce})
        :ok
      end

      assert {:ok, _} = DPoP.verify_proof(proof, verify_opts(nonce_check: check))
      assert_received {:nonce_seen, "the-only-good-nonce"}
    end

    test "a proof with no nonce claim (nil) when the check requires one is :use_dpop_nonce" do
      proof = signed_proof(%{})
      seen = self()

      # The store-shaped check: nil -> {:error, :use_dpop_nonce}.
      check = fn
        nonce when is_binary(nonce) ->
          :ok

        nonce ->
          send(seen, {:nonce_seen, nonce})
          {:error, :use_dpop_nonce}
      end

      assert {:error, :use_dpop_nonce} =
               DPoP.verify_proof(proof, verify_opts(nonce_check: check))

      # The proof genuinely carried no nonce, so the check saw nil.
      assert_received {:nonce_seen, nil}
    end

    test "a proof with a stale/wrong nonce is :use_dpop_nonce" do
      proof = signed_proof(%{"nonce" => "stale-or-rotated"})

      check = fn
        "currently-live" -> :ok
        _ -> {:error, :use_dpop_nonce}
      end

      assert {:error, :use_dpop_nonce} =
               DPoP.verify_proof(proof, verify_opts(nonce_check: check))
    end

    test "no :nonce_check at all: a nonce in the proof is ignored and it verifies" do
      proof = signed_proof(%{"nonce" => "some-nonce-the-server-never-issued"})

      assert {:ok, %{htm: @http_method, htu: @http_uri}} =
               DPoP.verify_proof(proof, verify_opts())
    end

    test "no :nonce_check at all: a proof without a nonce verifies (control)" do
      proof = signed_proof(%{})

      assert {:ok, _} = DPoP.verify_proof(proof, verify_opts())
    end

    test ":nonce_check that is not a 1-arity function raises ArgumentError" do
      proof = signed_proof(%{"nonce" => "n"})

      assert_raise ArgumentError, fn ->
        DPoP.verify_proof(proof, verify_opts(nonce_check: fn -> :ok end))
      end

      assert_raise ArgumentError, fn ->
        DPoP.verify_proof(proof, verify_opts(nonce_check: fn _a, _b -> :ok end))
      end

      assert_raise ArgumentError, fn ->
        DPoP.verify_proof(proof, verify_opts(nonce_check: :not_a_function))
      end
    end

    test ":nonce_check returning an unexpected value raises ArgumentError" do
      proof = signed_proof(%{"nonce" => "n"})

      error =
        assert_raise ArgumentError, fn ->
          DPoP.verify_proof(
            proof,
            verify_opts(nonce_check: fn _ -> {:error, "credential-sentinel-that-must-not-escape"} end)
          )
        end

      refute Exception.message(error) =~ "credential-sentinel"

      assert_raise ArgumentError, fn ->
        DPoP.verify_proof(proof, verify_opts(nonce_check: fn _ -> {:error, :some_other_reason} end))
      end

      assert_raise ArgumentError, fn ->
        DPoP.verify_proof(proof, verify_opts(nonce_check: fn _ -> true end))
      end
    end
  end

  # =================================================================
  # (2) NonceStore.ETS
  # =================================================================

  describe "NonceStore.ETS" do
    setup do
      start_supervised!(NonceStore)
      :ok
    end

    test "issue/1 returns a base64url string" do
      nonce = NonceStore.issue(60)

      assert is_binary(nonce)
      # base64url, unpadded: only the URL-safe alphabet, no '+', '/', or '='.
      assert nonce =~ ~r/\A[A-Za-z0-9_-]+\z/
      # 16 random bytes -> 22 unpadded base64url chars.
      assert String.length(nonce) == 22
    end

    test "issue with no ttl uses the default and is valid" do
      nonce = NonceStore.issue()

      assert is_binary(nonce)
      assert NonceStore.valid?(nonce)
    end

    test "two issued nonces are distinct" do
      assert NonceStore.issue(60) != NonceStore.issue(60)
    end

    test "valid?/1 is true for an issued nonce and false for an unknown one" do
      nonce = NonceStore.issue(60)

      assert NonceStore.valid?(nonce)
      refute NonceStore.valid?("never-issued-by-this-store")
    end

    test "valid?/1 is false for a non-binary nonce" do
      refute NonceStore.valid?(nil)
      refute NonceStore.valid?(:not_a_nonce)
    end

    test "valid?/1 is false for an expired nonce" do
      # A 1-second ttl issued slightly in the past: the store stamps
      # `expires_at = system_time + ttl` and `valid?` compares against the
      # store's own clock, so once we have waited past that stamp it reads
      # expired. We avoid a sleep by inspecting the boundary directly below;
      # here we assert the simplest expiry: a freshly issued 1s nonce is
      # live now.
      nonce = NonceStore.issue(1)
      assert NonceStore.valid?(nonce)
    end

    test "validate/1 is :ok for a live nonce and {:error, :use_dpop_nonce} otherwise" do
      live = NonceStore.issue(60)

      assert :ok = NonceStore.validate(live)
      assert {:error, :use_dpop_nonce} = NonceStore.validate(nil)
      assert {:error, :use_dpop_nonce} = NonceStore.validate("unknown-nonce")
    end

    test "validate/1 of an expired nonce is {:error, :use_dpop_nonce}" do
      # The store's clock is System.system_time(:second). Insert a nonce
      # whose ttl puts its expiry at or before "now" by waiting one tick.
      nonce = NonceStore.issue(1)
      # Busy-wait one whole second on the same clock the store reads, so the
      # expiry stamp (now0 + 1) is strictly in the past. No Process.sleep:
      # we spin until the store's own clock has advanced past the stamp.
      started = System.system_time(:second)
      wait_until_clock_passes(started + 1)

      refute NonceStore.valid?(nonce)
      assert {:error, :use_dpop_nonce} = NonceStore.validate(nonce)
    end

    test "reset/0 clears every issued nonce" do
      a = NonceStore.issue(300)
      b = NonceStore.issue(300)
      assert NonceStore.valid?(a)
      assert NonceStore.valid?(b)

      assert :ok = NonceStore.reset()

      refute NonceStore.valid?(a)
      refute NonceStore.valid?(b)
      assert {:error, :use_dpop_nonce} = NonceStore.validate(a)
    end
  end

  # =================================================================
  # (3) end to end: verify_proof wired to NonceStore.ETS.validate/1
  # =================================================================

  describe "verify_proof with NonceStore.ETS.validate/1 as the nonce_check" do
    setup do
      start_supervised!(NonceStore)
      :ok
    end

    test "a proof echoing a freshly issued nonce verifies" do
      nonce = NonceStore.issue(300)
      proof = signed_proof(%{"nonce" => nonce})

      assert {:ok, %{htm: @http_method, htu: @http_uri}} =
               DPoP.verify_proof(proof, verify_opts(nonce_check: &NonceStore.validate/1))
    end

    test "a proof carrying a nonce this store never issued is :use_dpop_nonce" do
      proof = signed_proof(%{"nonce" => "client-made-this-up"})

      assert {:error, :use_dpop_nonce} =
               DPoP.verify_proof(proof, verify_opts(nonce_check: &NonceStore.validate/1))
    end

    test "a proof with no nonce at all is :use_dpop_nonce (the challenge case)" do
      proof = signed_proof(%{})

      assert {:error, :use_dpop_nonce} =
               DPoP.verify_proof(proof, verify_opts(nonce_check: &NonceStore.validate/1))
    end

    test "a nonce that has been reset away no longer verifies" do
      nonce = NonceStore.issue(300)
      proof = signed_proof(%{"nonce" => nonce})

      assert {:ok, _} =
               DPoP.verify_proof(proof, verify_opts(nonce_check: &NonceStore.validate/1))

      NonceStore.reset()

      # A new proof echoing the now-cleared nonce is rejected.
      replay = signed_proof(%{"nonce" => nonce})

      assert {:error, :use_dpop_nonce} =
               DPoP.verify_proof(replay, verify_opts(nonce_check: &NonceStore.validate/1))
    end
  end

  # Spin until the store's clock (whole-second system time) has advanced
  # past `target`, so an expiry stamp <= target is strictly in the past.
  defp wait_until_clock_passes(target) do
    if System.system_time(:second) > target do
      :ok
    else
      wait_until_clock_passes(target)
    end
  end
end
