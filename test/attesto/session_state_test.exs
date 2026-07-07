defmodule Attesto.SessionStateTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.SessionState

  describe "compute/4" do
    test "matches the Session Management 1.0 §3.2 recipe (lowercase hex + \".\" + salt)" do
      # Independently computed: hex(SHA256("client-a https://rp.example opbs-1 salt-1")).
      expected_hash =
        :sha256
        |> :crypto.hash("client-a https://rp.example opbs-1 salt-1")
        |> Base.encode16(case: :lower)

      assert SessionState.compute("client-a", "https://rp.example", "opbs-1", "salt-1") ==
               expected_hash <> "." <> "salt-1"
    end

    test "is deterministic for the same inputs and differs when any input changes" do
      base = SessionState.compute("c", "https://rp.example", "state", "salt")

      assert base == SessionState.compute("c", "https://rp.example", "state", "salt")
      refute base == SessionState.compute("c2", "https://rp.example", "state", "salt")
      refute base == SessionState.compute("c", "https://rp2.example", "state", "salt")
      refute base == SessionState.compute("c", "https://rp.example", "state2", "salt")
      refute base == SessionState.compute("c", "https://rp.example", "state", "salt2")
    end

    test "contains no space character (§2)" do
      value = SessionState.compute("client a", "https://rp.example", "op state")
      refute value =~ " "
    end

    test "defaults to a fresh salt per call" do
      a = SessionState.compute("c", "https://rp.example", "s")
      b = SessionState.compute("c", "https://rp.example", "s")
      refute a == b
    end
  end

  describe "origin/1" do
    test "drops path, query, and fragment" do
      assert SessionState.origin("https://rp.example/cb?x=1#f") == {:ok, "https://rp.example"}
    end

    test "omits the scheme default port, keeps a non-default port" do
      assert SessionState.origin("https://rp.example:443/cb") == {:ok, "https://rp.example"}
      assert SessionState.origin("http://rp.example:80/cb") == {:ok, "http://rp.example"}
      assert SessionState.origin("https://rp.example:8443/cb") == {:ok, "https://rp.example:8443"}
    end

    test "rejects a URI without scheme or host" do
      assert SessionState.origin("/relative/path") == {:error, :invalid_uri}
      assert SessionState.origin("not a uri") == {:error, :invalid_uri}
    end
  end

  describe "generated values" do
    test "salts and browser states are URL-safe, dot-free, and unique" do
      salts = for _ <- 1..32, do: SessionState.generate_salt()
      states = for _ <- 1..32, do: SessionState.generate_browser_state()

      for value <- salts ++ states do
        assert value =~ ~r/\A[A-Za-z0-9_-]+\z/
      end

      assert length(Enum.uniq(salts)) == 32
      assert length(Enum.uniq(states)) == 32
    end
  end

  describe "mint_browser_state/2 + browser_state_valid?/3 (OP-owned, login-bound)" do
    @secret :crypto.strong_rand_bytes(32)
    @binding "user-42\n1700000000\nsid-1"

    test "a freshly minted value verifies for its own secret and login binding" do
      value = SessionState.mint_browser_state(@secret, @binding)
      assert SessionState.browser_state_valid?(@secret, value, @binding)
    end

    test "the value is a valid op_browser_state: no space, three base64url parts" do
      value = SessionState.mint_browser_state(@secret, @binding)

      refute value =~ " "
      assert [random, login_tag, mac] = String.split(value, ".", parts: 3)

      for part <- [random, login_tag, mac] do
        assert part =~ ~r/\A[A-Za-z0-9_-]+\z/
      end
    end

    test "each mint has fresh random entropy (values differ) but all verify" do
      values = for _ <- 1..16, do: SessionState.mint_browser_state(@secret, @binding)

      assert length(Enum.uniq(values)) == 16
      assert Enum.all?(values, &SessionState.browser_state_valid?(@secret, &1, @binding))
    end

    test "a value not minted by this OP (wrong/forged) is rejected" do
      value = SessionState.mint_browser_state(@secret, @binding)

      # Wrong secret.
      refute SessionState.browser_state_valid?(:crypto.strong_rand_bytes(32), value, @binding)
      # An attacker-known, un-MAC'd string (the injected-cookie attack).
      refute SessionState.browser_state_valid?(@secret, "known-injected-value", @binding)
      # A tampered MAC.
      [random, login_tag, _mac] = String.split(value, ".", parts: 3)
      refute SessionState.browser_state_valid?(@secret, "#{random}.#{login_tag}.forged", @binding)
    end

    test "a value bound to a different login state is rejected (rotation trigger)" do
      value = SessionState.mint_browser_state(@secret, @binding)

      refute SessionState.browser_state_valid?(@secret, value, "user-42\n1700009999\nsid-1")
      refute SessionState.browser_state_valid?(@secret, value, "user-99\n1700000000\nsid-1")
      refute SessionState.browser_state_valid?(@secret, value, "user-42\n1700000000\nsid-2")
      # Still valid for the exact same binding.
      assert SessionState.browser_state_valid?(@secret, value, @binding)
    end

    test "a swapped login_tag from a valid value does not verify (login tag is MAC-bound)" do
      value = SessionState.mint_browser_state(@secret, "user-1\n1\n")
      other = SessionState.mint_browser_state(@secret, "user-2\n2\n")
      [random, _tag, mac] = String.split(value, ".", parts: 3)
      [_r2, other_tag, _m2] = String.split(other, ".", parts: 3)

      # Splice user-2's login tag onto user-1's value: the MAC no longer covers it.
      refute SessionState.browser_state_valid?(@secret, "#{random}.#{other_tag}.#{mac}", "user-2\n2\n")
    end
  end
end
