defmodule Attesto.URITest do
  use ExUnit.Case, async: true

  alias Attesto.URI, as: AttestoURI

  test "accepts absolute HTTPS identifiers" do
    assert AttestoURI.https_identifier?("https://resource.example/path?x=1")
    assert AttestoURI.https_identifier?("https://[2001:db8::1]:8443/path")
    assert AttestoURI.https_identifier?("https://resource.example/%2e%2e")
  end

  test "HTTP requires an explicit opt-in" do
    refute AttestoURI.https_identifier?("http://127.0.0.1:4000/resource")
    assert AttestoURI.https_identifier?("http://127.0.0.1:4000/resource", allow_http: true)
  end

  test "rejects authority and encoding hazards" do
    for value <- [
          "https://user:password@resource.example/path",
          "https://resource.example/path#fragment",
          "https:///path",
          "https://resource.example/%ZZ",
          "https://resource.example/%2",
          "https://resource.example/a b",
          "https://resource.example/\x01",
          <<255>>,
          "/relative",
          "",
          nil
        ] do
      refute AttestoURI.https_identifier?(value)
    end
  end

  test "invalid options fail closed" do
    refute AttestoURI.https_identifier?("https://resource.example", allow_http: :yes)
    refute AttestoURI.https_identifier?("https://resource.example", %{allow_http: true})
  end
end
