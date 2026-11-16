defmodule Attesto.LogMessagesTest do
  use ExUnit.Case, async: true

  alias Attesto.Test.LogMessages

  test "error logs use documented fixed literal messages" do
    calls = LogMessages.errors("lib")
    assert calls != []
    assert Enum.filter(calls, &is_nil(&1.message)) == []
    documentation = File.read!("README.md")
    for call <- calls, do: assert(documentation =~ call.message)
  end
end
