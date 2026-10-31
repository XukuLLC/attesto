defmodule Attesto.StrictJSONTest do
  use ExUnit.Case, async: true

  alias Attesto.StrictJSON

  test "decodes valid JSON objects and preserves nested arrays and objects" do
    assert {:ok, %{"a" => 1, "b" => ["x", %{"c" => true}]}} =
             StrictJSON.decode(~s({"a":1,"b":["x",{"c":true}]}))
  end

  test "rejects duplicate keys at the top level and in nested objects" do
    assert {:error, :invalid_json} = StrictJSON.decode(~s({"a":1,"a":2}))
    assert {:error, :invalid_json} = StrictJSON.decode(~s({"nested":{"a":1,"a":2}}))
    assert {:error, :invalid_json} = StrictJSON.decode(~s({"arr":[{"a":1,"a":2}]}))
  end

  test "rejects non-object top-level JSON values and non-binary inputs" do
    for invalid <- [~s([1,2]), ~s("str"), ~s(123), ~s(true), ~s(null), "not json", ""] do
      assert {:error, :invalid_json} = StrictJSON.decode(invalid)
    end

    assert {:error, :invalid_json} = StrictJSON.decode(Process.get(:never_set, 123))
    assert {:error, :invalid_json} = StrictJSON.decode("{}", Process.get(:never_set, :bad_opts))
  end

  test "enforces :max_json_depth" do
    assert {:ok, %{"a" => %{"b" => 1}}} = StrictJSON.decode(~s({"a":{"b":1}}), max_json_depth: 2)
    assert {:error, :invalid_json} = StrictJSON.decode(~s({"a":{"b":1}}), max_json_depth: 1)
    assert {:error, :invalid_json} = StrictJSON.decode(~s({"a":[1]}), max_depth: 1)
    assert {:error, :invalid_json} = StrictJSON.decode(~s({"a":1}), max_json_depth: 0)
  end
end
