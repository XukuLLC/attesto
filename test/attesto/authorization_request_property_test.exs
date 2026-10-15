defmodule Attesto.AuthorizationRequestPropertyTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Attesto.AuthorizationRequest
  alias Attesto.PKCE

  @verifier "authreq-property-verifier-unreserved_aaaaaaaaaaaa~0"
  @scope_tokens ~w(openid profile email documents.read documents.write offline_access)

  setup_all do
    {:ok, challenge} = PKCE.challenge(@verifier)
    %{challenge: challenge}
  end

  describe "validate/2 properties" do
    property "valid requests normalize scope, OIDC flag, state, nonce, prompt, acr, and max_age", %{
      challenge: challenge
    } do
      check all(
              client_suffix <- suffix_generator(),
              redirect_suffix <- suffix_generator(),
              scopes <- list_of(member_of(@scope_tokens), max_length: 8),
              state <- one_of([constant(nil), suffix_generator()]),
              nonce <- one_of([constant(nil), suffix_generator()]),
              prompt <- valid_prompt_generator(),
              acr_values <- list_of(member_of(["urn:mace:incommon:iap:silver", "phr", "loa2"]), max_length: 4),
              max_age <- one_of([constant(nil), integer(0..86_400)]),
              max_runs: 80
            ) do
        redirect_uri = "https://client.example/cb/" <> redirect_suffix
        scope_string = Enum.join(scopes, " ")

        params =
          %{
            "response_type" => "code",
            "client_id" => "client-" <> client_suffix,
            "redirect_uri" => redirect_uri,
            "scope" => scope_string,
            "code_challenge" => challenge,
            "code_challenge_method" => "S256"
          }
          |> maybe_put("state", state)
          |> maybe_put("nonce", nonce)
          |> maybe_put("prompt", Enum.join(prompt, " "))
          |> maybe_put("acr_values", Enum.join(acr_values, " "))
          |> maybe_put("max_age", max_age)

        assert {:ok, req} =
                 AuthorizationRequest.validate(params,
                   registered_redirect_uris: [redirect_uri, "https://client.example/other"]
                 )

        assert req.client_id == "client-" <> client_suffix
        assert req.redirect_uri == redirect_uri
        assert req.scope == scopes
        assert req.openid? == "openid" in scopes
        assert req.state == state
        assert req.nonce == nonce
        assert req.prompt == prompt
        assert req.acr_values == acr_values
        assert req.max_age == max_age
      end
    end

    property "untrusted redirect_uri failures are direct and take priority over redirectable errors", %{
      challenge: challenge
    } do
      check all(
              evil_suffix <- suffix_generator(),
              bad_response_type <- member_of(["token", "id_token", "code token", ""]),
              max_runs: 80
            ) do
        params = %{
          "response_type" => bad_response_type,
          "client_id" => "client-123",
          "redirect_uri" => "https://evil.example/cb/" <> evil_suffix,
          "code_challenge" => challenge,
          "code_challenge_method" => "S256"
        }

        assert {:error, {:direct, :redirect_uri_not_registered}} =
                 AuthorizationRequest.validate(params,
                   registered_redirect_uris: ["https://client.example/cb"]
                 )
      end
    end

    property "redirectable errors echo only a trusted redirect_uri and optional state", %{challenge: challenge} do
      check all(
              state <- one_of([constant(nil), suffix_generator()]),
              failure <- member_of([:response_type, :scope, :pkce_method, :max_age]),
              max_runs: 80
            ) do
        redirect_uri = "https://client.example/cb"

        params =
          %{
            "response_type" => "code",
            "client_id" => "client-123",
            "redirect_uri" => redirect_uri,
            "scope" => "openid",
            "code_challenge" => challenge,
            "code_challenge_method" => "S256"
          }
          |> maybe_put("state", state)
          |> corrupt_for(failure)

        assert {:error, {:redirect, err}} =
                 AuthorizationRequest.validate(params, registered_redirect_uris: [redirect_uri])

        assert err.redirect_uri == redirect_uri
        assert err.state == state
        assert err.error in ["invalid_request", "invalid_scope", "unsupported_response_type"]
      end
    end
  end

  defp corrupt_for(params, :response_type), do: Map.put(params, "response_type", "token")
  defp corrupt_for(params, :scope), do: Map.put(params, "scope", "open\"id")
  defp corrupt_for(params, :pkce_method), do: Map.put(params, "code_challenge_method", "plain")
  defp corrupt_for(params, :max_age), do: Map.put(params, "max_age", "-1")

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp suffix_generator do
    gen all(chars <- list_of(member_of(Enum.concat([?a..?z, ?0..?9])), min_length: 1, max_length: 16)) do
      List.to_string(chars)
    end
  end

  defp valid_prompt_generator do
    one_of([
      list_of(member_of(~w(login consent select_account)), max_length: 4),
      list_of(constant("none"), min_length: 1, max_length: 4)
    ])
  end
end
