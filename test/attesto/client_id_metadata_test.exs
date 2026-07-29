defmodule Attesto.ClientIdMetadataTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.ClientIdMetadata

  describe "validate_client_id/1 URL grammar (draft §2)" do
    test "accepts an https URL with a path" do
      assert {:ok, %URI{} = uri} = ClientIdMetadata.validate_client_id("https://app.example/cb")
      assert uri.scheme == "https"
      assert uri.host == "app.example"
      assert uri.path == "/cb"
    end

    test "accepts an https URL with a port and a query" do
      assert {:ok, %URI{}} =
               ClientIdMetadata.validate_client_id("https://app.example:8443/client?v=1")
    end

    test "rejects a non-https scheme" do
      assert {:error, :not_https} = ClientIdMetadata.validate_client_id("http://app.example/cb")
    end

    test "rejects a URL with no path" do
      assert {:error, :no_path} = ClientIdMetadata.validate_client_id("https://app.example")
    end

    test "rejects a URL whose only path is a bare slash" do
      assert {:error, :no_path} = ClientIdMetadata.validate_client_id("https://app.example/")
    end

    test "rejects a URL with a fragment" do
      assert {:error, :has_fragment} =
               ClientIdMetadata.validate_client_id("https://app.example/cb#frag")
    end

    test "rejects a URL with userinfo" do
      assert {:error, :has_userinfo} =
               ClientIdMetadata.validate_client_id("https://user:pass@app.example/cb")
    end

    test "rejects a single-dot path segment" do
      assert {:error, :dot_segments} =
               ClientIdMetadata.validate_client_id("https://app.example/./cb")
    end

    test "rejects a double-dot path segment" do
      assert {:error, :dot_segments} =
               ClientIdMetadata.validate_client_id("https://app.example/a/../cb")
    end

    test "rejects a value that does not parse as a URL with a host" do
      assert {:error, :not_a_url} = ClientIdMetadata.validate_client_id("not a url")
      assert {:error, :not_a_url} = ClientIdMetadata.validate_client_id("/relative/path")
    end
  end

  describe "client_id_url?/1" do
    test "true for a well-formed CIMD client_id URL" do
      assert ClientIdMetadata.client_id_url?("https://app.example/cb")
    end

    test "false for a URL that fails the grammar" do
      refute ClientIdMetadata.client_id_url?("http://app.example/cb")
      refute ClientIdMetadata.client_id_url?("https://app.example")
      refute ClientIdMetadata.client_id_url?("https://app.example/a/../cb")
    end

    test "false for an opaque (non-URL) client_id" do
      refute ClientIdMetadata.client_id_url?("oc_abc123")
    end

    test "false for a non-binary term" do
      refute ClientIdMetadata.client_id_url?(nil)
      refute ClientIdMetadata.client_id_url?(%{})
      refute ClientIdMetadata.client_id_url?(123)
    end
  end

  describe "validate_document/2 client_id binding (draft §2)" do
    test "accepts a document whose client_id matches the URL" do
      client_id = "https://app.example/cb"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/callback"]
      }

      assert {:ok, metadata} = ClientIdMetadata.validate_document(client_id, doc)
      assert metadata["client_id"] == client_id
    end

    test "rejects a document whose client_id does not match the URL" do
      doc = %{
        "client_id" => "https://other.example/cb",
        "redirect_uris" => ["https://app.example/callback"]
      }

      assert {:error, :client_id_mismatch} =
               ClientIdMetadata.validate_document("https://app.example/cb", doc)
    end

    test "rejects a document with no client_id member" do
      doc = %{"redirect_uris" => ["https://app.example/callback"]}

      assert {:error, :client_id_mismatch} =
               ClientIdMetadata.validate_document("https://app.example/cb", doc)
    end
  end

  describe "validate_document/2 symmetric secret rejection (draft §2)" do
    test "rejects a document carrying client_secret" do
      client_id = "https://app.example/cb"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/callback"],
        "client_secret" => "s3cret"
      }

      assert {:error, :symmetric_secret} = ClientIdMetadata.validate_document(client_id, doc)
    end

    test "rejects a document carrying client_secret_expires_at" do
      client_id = "https://app.example/cb"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/callback"],
        "client_secret_expires_at" => 0
      }

      assert {:error, :symmetric_secret} = ClientIdMetadata.validate_document(client_id, doc)
    end
  end

  describe "validate_document/2 symmetric auth method rejection (draft §2)" do
    for method <- ~w(client_secret_basic client_secret_post client_secret_jwt) do
      test "rejects token_endpoint_auth_method #{method}" do
        client_id = "https://app.example/cb"

        doc = %{
          "client_id" => client_id,
          "redirect_uris" => ["https://app.example/callback"],
          "token_endpoint_auth_method" => unquote(method)
        }

        assert {:error, :symmetric_auth_method} =
                 ClientIdMetadata.validate_document(client_id, doc)
      end
    end

    test "accepts token_endpoint_auth_method none" do
      client_id = "https://app.example/cb"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/callback"],
        "token_endpoint_auth_method" => "none"
      }

      assert {:ok, metadata} = ClientIdMetadata.validate_document(client_id, doc)
      assert metadata["token_endpoint_auth_method"] == "none"
    end

    test "accepts token_endpoint_auth_method private_key_jwt" do
      client_id = "https://app.example/cb"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/callback"],
        "token_endpoint_auth_method" => "private_key_jwt"
      }

      assert {:ok, metadata} = ClientIdMetadata.validate_document(client_id, doc)
      assert metadata["token_endpoint_auth_method"] == "private_key_jwt"
    end
  end

  describe "validate_document/2 redirect_uris (RFC 9700)" do
    test "extracts a non-empty list of redirect_uris" do
      client_id = "https://app.example/cb"
      uris = ["https://app.example/callback", "https://app.example/callback2"]

      doc = %{"client_id" => client_id, "redirect_uris" => uris}

      assert {:ok, metadata} = ClientIdMetadata.validate_document(client_id, doc)
      assert metadata["redirect_uris"] == uris
    end

    test "rejects an absent redirect_uris" do
      client_id = "https://app.example/cb"
      doc = %{"client_id" => client_id}

      assert {:error, :invalid_redirect_uris} =
               ClientIdMetadata.validate_document(client_id, doc)
    end

    test "rejects an empty redirect_uris" do
      client_id = "https://app.example/cb"
      doc = %{"client_id" => client_id, "redirect_uris" => []}

      assert {:error, :invalid_redirect_uris} =
               ClientIdMetadata.validate_document(client_id, doc)
    end

    test "rejects a redirect_uris that is not a list of strings" do
      client_id = "https://app.example/cb"
      doc = %{"client_id" => client_id, "redirect_uris" => ["https://app.example/cb", 42]}

      assert {:error, :invalid_redirect_uris} =
               ClientIdMetadata.validate_document(client_id, doc)
    end

    # A CIMD document is fetched from a URL the client chose, so its
    # `redirect_uris` are attacker-supplied. One whose authority two URL parsers
    # read differently would let the same-origin tightening approve a host the
    # browser never navigates to, so it never enters the registered set.
    test "rejects a redirect_uri whose host depends on which parser reads it" do
      client_id = "https://app.example/meta"

      for uri <- [
            "https://evil.example\\@app.example/cb",
            "https://evil.example@app.example/cb",
            "https://evil.example\t@app.example/cb",
            "https://app.example/c b"
          ] do
        doc = %{"client_id" => client_id, "redirect_uris" => [uri]}

        assert {:error, :invalid_redirect_uris} =
                 ClientIdMetadata.validate_document(client_id, doc),
               "expected #{inspect(uri)} to be rejected"
      end
    end

    test "rejects the whole document when only one redirect_uri is ambiguous" do
      client_id = "https://app.example/meta"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/cb", "https://evil.example\\@app.example/cb"]
      }

      assert {:error, :invalid_redirect_uris} =
               ClientIdMetadata.validate_document(client_id, doc)
    end
  end

  describe "validate_document/2 normalization (RFC 7591 §2)" do
    test "carries through the known metadata members and drops unknown ones" do
      client_id = "https://app.example/cb"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/callback"],
        "grant_types" => ["authorization_code", "refresh_token"],
        "response_types" => ["code"],
        "scope" => "openid profile",
        "client_name" => "Example App",
        "client_uri" => "https://app.example",
        "logo_uri" => "https://app.example/logo.png",
        "jwks_uri" => "https://app.example/jwks.json",
        "contacts" => ["ops@app.example"],
        "jwks" => %{"keys" => []},
        "software_statement" => "ignored"
      }

      assert {:ok, metadata} = ClientIdMetadata.validate_document(client_id, doc)

      assert metadata["grant_types"] == ["authorization_code", "refresh_token"]
      assert metadata["response_types"] == ["code"]
      assert metadata["scope"] == "openid profile"
      assert metadata["client_name"] == "Example App"
      assert metadata["client_uri"] == "https://app.example"
      assert metadata["logo_uri"] == "https://app.example/logo.png"
      assert metadata["jwks_uri"] == "https://app.example/jwks.json"
      assert metadata["contacts"] == ["ops@app.example"]
      assert metadata["jwks"] == %{"keys" => []}

      refute Map.has_key?(metadata, "software_statement")
    end

    test "omits absent members rather than rendering them as nil" do
      client_id = "https://app.example/cb"
      doc = %{"client_id" => client_id, "redirect_uris" => ["https://app.example/callback"]}

      assert {:ok, metadata} = ClientIdMetadata.validate_document(client_id, doc)

      refute Map.has_key?(metadata, "scope")
      refute Map.has_key?(metadata, "grant_types")
      refute Map.has_key?(metadata, "jwks")
    end

    test "rejects a member of the wrong shape" do
      client_id = "https://app.example/cb"

      doc = %{
        "client_id" => client_id,
        "redirect_uris" => ["https://app.example/callback"],
        "grant_types" => "authorization_code"
      }

      assert {:error, :invalid_metadata} =
               ClientIdMetadata.validate_document(client_id, doc)
    end
  end
end
