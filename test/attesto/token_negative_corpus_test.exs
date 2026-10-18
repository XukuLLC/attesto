defmodule Attesto.TokenNegativeCorpusTest do
  @moduledoc false
  # Replays the frozen negative-JWT corpus in test/fixtures/jwt_corpus/
  # against Attesto.Token.verify/3 and asserts each token produces exactly
  # the error atom its companion `.json` records.
  #
  # Where the surrounding suite round-trips through Token.mint/3, these
  # fixtures are *frozen bytes* a mint helper can never emit - non-URL-safe
  # base64, non-UTF-8 payloads, control characters in the JSON, padding
  # remnants, segment-count anomalies, hand-planted `crit`/`kid` attacks.
  # They pin the wire-level contract so a parser regression surfaces as a
  # corpus failure here rather than a silently changed code path. See the
  # corpus README for the layout and the per-group expected-error table.
  #
  # The corpus was signed with a fixed key (signing_key.pem) and minted
  # against a frozen clock; the config below mirrors the one it was produced
  # under (Factory.config/1 - same issuer/audience and client/user principal
  # kinds), and every fixture is verified with `now: @frozen_now`. The module
  # installs that key into the Attesto.Keystore.Static singleton, so it is
  # `async: false`.
  use ExUnit.Case, async: false

  alias Attesto.Test.Factory
  alias Attesto.Token

  @corpus_dir Path.expand("../fixtures/jwt_corpus", __DIR__)

  # The frozen instant the temporal fixtures (exp==now, future nbf/iat) were
  # minted against; verifying at any other time would drift those edges.
  @frozen_now 1_700_000_000

  # Globbed at compile time so each fixture becomes its own named test (a
  # failure points at the exact attack vector, not an opaque loop index).
  @fixtures @corpus_dir |> Path.join("*.jwt") |> Path.wildcard() |> Enum.sort()

  setup do
    pem = File.read!(Path.join(@corpus_dir, "signing_key.pem"))
    {:ok, config: Factory.config(pem)}
  end

  test "the corpus is present and every .jwt has a .json sidecar" do
    assert @fixtures != [], "no fixtures found under #{@corpus_dir}"

    for jwt_path <- @fixtures do
      assert File.exists?(Path.rootname(jwt_path) <> ".json"),
             "#{Path.basename(jwt_path)} has no companion .json"
    end
  end

  for jwt_path <- @fixtures do
    @jwt_path jwt_path
    @meta_path Path.rootname(jwt_path) <> ".json"
    stem = Path.basename(jwt_path, ".jwt")

    test "negative corpus: #{stem}", %{config: config} do
      jwt = File.read!(@jwt_path)
      meta = @meta_path |> File.read!() |> JSON.decode!()
      vector = meta["attack_vector"]
      result = Token.verify(config, jwt, now: @frozen_now)

      case meta["expected_error"] do
        "ok" ->
          assert {:ok, _claims} = result,
                 "#{meta["name"]} (#{vector}) expected to verify cleanly, got #{inspect(result)}"

        error_string ->
          expected = String.to_existing_atom(error_string)

          assert {:error, expected} == result,
                 "#{meta["name"]} (#{vector}) expected {:error, #{inspect(expected)}}, got #{inspect(result)}"
      end
    end
  end
end
