defmodule Attesto.FrontChannelLogoutTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Config
  alias Attesto.FrontChannelLogout
  alias Attesto.Keystore.Static
  alias Attesto.PrincipalKind

  defp config do
    Config.new(
      issuer: "https://op.example",
      audience: "https://api.example",
      keystore: Static,
      principal_kinds: [PrincipalKind.new("client", "oc_")]
    )
  end

  describe "logout_uri/3" do
    test "appends iss and sid when the session id is known" do
      uri = FrontChannelLogout.logout_uri(config(), "https://rp.example/fc", "sess-1")

      assert uri == "https://rp.example/fc?iss=https%3A%2F%2Fop.example&sid=sess-1"
    end

    test "the appended parameters round-trip through query decoding" do
      uri = FrontChannelLogout.logout_uri(config(), "https://rp.example/fc", "sess/+=1")
      %URI{query: query} = URI.parse(uri)
      decoded = URI.decode_query(query)

      assert decoded == %{"iss" => "https://op.example", "sid" => "sess/+=1"}
    end

    test "preserves a query the RP registered on the URI" do
      uri = FrontChannelLogout.logout_uri(config(), "https://rp.example/fc?a=b", "sess-1")
      %URI{query: query} = URI.parse(uri)

      assert URI.decode_query(query) == %{
               "a" => "b",
               "iss" => "https://op.example",
               "sid" => "sess-1"
             }
    end

    test "with no sid the URI is returned unchanged (iss-only is never produced)" do
      # Front-Channel Logout 1.0 §2: if either of iss/sid is included, both
      # MUST be — so an unknown session id yields the bare registered URI.
      assert FrontChannelLogout.logout_uri(config(), "https://rp.example/fc", nil) ==
               "https://rp.example/fc"

      assert FrontChannelLogout.logout_uri(config(), "https://rp.example/fc", "") ==
               "https://rp.example/fc"
    end
  end
end
