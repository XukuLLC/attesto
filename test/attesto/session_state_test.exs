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
end
