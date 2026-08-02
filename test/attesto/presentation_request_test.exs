defmodule Attesto.PresentationRequestTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.PresentationRequest

  @client_id "https://verifier.example.com"
  @nonce "nonce-123"
  @response_uri "https://verifier.example.com/callback"

  defp credential_query do
    %{
      id: "identity",
      format: "dc+sd-jwt",
      meta: %{vct_values: ["IdentityCredential"]},
      claims: [%{path: ["credentialSubject", "given_name"]}]
    }
  end

  defp dcql_query do
    PresentationRequest.dcql_query(credentials: [credential_query()])
  end

  defp required_opts do
    [client_id: @client_id, nonce: @nonce, response_uri: @response_uri, dcql_query: dcql_query()]
  end

  test "builds a minimal request" do
    request = PresentationRequest.build(required_opts())

    assert request["client_id"] == @client_id
    assert request["nonce"] == @nonce
    assert request["response_uri"] == @response_uri
    assert request["response_type"] == "vp_token"
    assert request["response_mode"] == "direct_post"
    assert request["dcql_query"] == dcql_query()
    assert Enum.all?(Map.keys(request), &is_binary/1)
  end

  test "accepts direct_post.jwt and rejects other response modes" do
    assert PresentationRequest.build(required_opts() ++ [response_mode: "direct_post.jwt"])[
             "response_mode"
           ] == "direct_post.jwt"

    for response_mode <- ["query", "fragment", "", nil, :direct_post] do
      assert_raise ArgumentError, ~r/:response_mode must be/, fn ->
        PresentationRequest.build(required_opts() ++ [response_mode: response_mode])
      end
    end
  end

  test "requires client_id, nonce, response_uri, and dcql_query" do
    for key <- [:client_id, :nonce, :response_uri, :dcql_query] do
      assert_raise ArgumentError, fn ->
        PresentationRequest.build(Keyword.delete(required_opts(), key))
      end
    end
  end

  test "includes supplied optional values and drops nil values" do
    request =
      PresentationRequest.build(
        required_opts() ++
          [
            state: "state-123",
            client_metadata: %{"jwks" => %{"keys" => []}},
            client_id_scheme: "redirect_uri",
            aud: "https://verifier.example.com/audience"
          ]
      )

    assert request["state"] == "state-123"
    assert request["client_metadata"] == %{"jwks" => %{"keys" => []}}
    assert request["client_id_scheme"] == "redirect_uri"
    refute Map.has_key?(request, "aud")

    nil_request =
      PresentationRequest.build(required_opts() ++ [state: nil, client_metadata: nil, client_id_scheme: nil])

    refute Map.has_key?(nil_request, "state")
    refute Map.has_key?(nil_request, "client_metadata")
    refute Map.has_key?(nil_request, "client_id_scheme")
  end

  test "builds a string-keyed DCQL query and drops nil optional fields" do
    query =
      PresentationRequest.dcql_query(
        credentials: [
          %{
            id: "identity",
            format: "dc+sd-jwt",
            meta: %{vct_values: ["IdentityCredential"]},
            claims: [
              %{path: ["credentialSubject", "given_name"], values: ["Neil"], id: nil},
              %{path: ["credentialSubject", 0, nil], values: nil}
            ]
          }
        ]
      )

    assert query == %{
             "credentials" => [
               %{
                 "id" => "identity",
                 "format" => "dc+sd-jwt",
                 "meta" => %{"vct_values" => ["IdentityCredential"]},
                 "claims" => [
                   %{
                     "path" => ["credentialSubject", "given_name"],
                     "values" => ["Neil"]
                   },
                   %{"path" => ["credentialSubject", 0, nil]}
                 ]
               }
             ]
           }
  end

  test "accepts atom-keyed and string-keyed DCQL input identically" do
    atom_keyed =
      PresentationRequest.dcql_query(
        credentials: [
          %{
            id: "identity",
            format: "dc+sd-jwt",
            meta: %{vct_values: ["IdentityCredential"]},
            claims: [%{path: ["credentialSubject", "given_name"]}]
          }
        ]
      )

    string_keyed =
      PresentationRequest.dcql_query(%{
        "credentials" => [
          %{
            "id" => "identity",
            "format" => "dc+sd-jwt",
            "meta" => %{"vct_values" => ["IdentityCredential"]},
            "claims" => [%{"path" => ["credentialSubject", "given_name"]}]
          }
        ]
      })

    assert atom_keyed == string_keyed
  end

  test "rejects invalid DCQL credentials, IDs, formats, paths, and vct_values" do
    invalid_queries = [
      %{credentials: []},
      %{credentials: [%{format: "dc+sd-jwt"}]},
      %{credentials: [%{id: "identity"}]},
      %{credentials: [%{id: "identity", format: "dc+sd-jwt"}, %{id: "identity", format: "dc+sd-jwt"}]},
      %{credentials: [%{id: "identity", format: "dc+sd-jwt", claims: [%{path: []}]}]},
      %{credentials: [%{id: "identity", format: "dc+sd-jwt", claims: [%{}]}]},
      %{credentials: [%{id: "identity", format: "dc+sd-jwt", meta: %{vct_values: []}}]},
      %{credentials: [%{id: "identity", format: "dc+sd-jwt", meta: %{vct_values: ["ok", 1]}}]}
    ]

    for query <- invalid_queries do
      assert_raise ArgumentError, fn -> PresentationRequest.dcql_query(query) end
    end
  end

  test "round-trips the query string" do
    request =
      PresentationRequest.build(
        required_opts() ++ [client_metadata: %{"vp_formats_supported" => %{"dc+sd-jwt" => %{}}}]
      )

    params = request |> PresentationRequest.to_query_string() |> URI.decode_query()

    assert params["client_id"] == @client_id
    assert params["nonce"] == @nonce
    assert params["response_uri"] == @response_uri
    assert params["response_type"] == "vp_token"
    assert params["response_mode"] == "direct_post"
    assert JSON.decode!(params["dcql_query"]) == request["dcql_query"]
    assert JSON.decode!(params["client_metadata"]) == request["client_metadata"]
  end
end
