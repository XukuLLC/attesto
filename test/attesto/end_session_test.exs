defmodule Attesto.EndSessionTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.EndSession
  alias Attesto.IDToken
  alias Attesto.Test.Factory

  @client_id "client-abc"
  @subject "usr_end_user_1"
  @sid "sess-123"

  setup do
    pem = Factory.rsa_pem()
    config = Factory.config(pem)
    {:ok, hint} = IDToken.mint(config, @subject, @client_id, sid: @sid)
    {:ok, config: config, hint: hint}
  end

  describe "parse/2 with id_token_hint" do
    test "extracts client_id, subject and sid from a valid hint", %{config: config, hint: hint} do
      assert {:ok, request} = EndSession.parse(config, %{"id_token_hint" => hint})
      assert request.client_id == @client_id
      assert request.subject == @subject
      assert request.sid == @sid
    end

    test "tolerates an expired hint (RP-Initiated Logout §2)", %{config: config} do
      # iat/exp in the past; verify_logout_hint must still accept it.
      past = 1_500_000_000
      {:ok, expired} = IDToken.mint(config, @subject, @client_id, sid: @sid, now: past)
      assert {:ok, request} = EndSession.parse(config, %{"id_token_hint" => expired})
      assert request.client_id == @client_id
      assert request.sid == @sid
    end

    test "a tampered hint is :invalid_id_token_hint", %{config: config, hint: hint} do
      tampered = hint <> "x"
      assert {:error, :invalid_id_token_hint} = EndSession.parse(config, %{"id_token_hint" => hint <> "garbage"})
      # also a structurally-broken token
      assert {:error, :invalid_id_token_hint} = EndSession.parse(config, %{"id_token_hint" => "not.a.jwt"})
      _ = tampered
    end

    test "a client_id param disagreeing with the hint aud is :client_id_mismatch", %{config: config, hint: hint} do
      assert {:error, :client_id_mismatch} =
               EndSession.parse(config, %{"id_token_hint" => hint, "client_id" => "other-client"})
    end

    test "a client_id param matching the hint aud is accepted", %{config: config, hint: hint} do
      assert {:ok, request} = EndSession.parse(config, %{"id_token_hint" => hint, "client_id" => @client_id})
      assert request.client_id == @client_id
    end
  end

  describe "parse/2 without id_token_hint" do
    test "uses the client_id param and leaves session ids nil", %{config: config} do
      assert {:ok, request} =
               EndSession.parse(config, %{
                 "client_id" => @client_id,
                 "post_logout_redirect_uri" => "https://rp.example/after",
                 "state" => "xyz"
               })

      assert request.client_id == @client_id
      assert request.subject == nil
      assert request.sid == nil
      assert request.post_logout_redirect_uri == "https://rp.example/after"
      assert request.state == "xyz"
    end

    test "no hint and no client_id leaves client_id nil", %{config: config} do
      assert {:ok, request} = EndSession.parse(config, %{})
      assert request.client_id == nil
    end
  end

  describe "confirm_redirect/2" do
    test "no requested uri yields :no_redirect", %{config: config} do
      {:ok, request} = EndSession.parse(config, %{"client_id" => @client_id})
      assert {:ok, :no_redirect} = EndSession.confirm_redirect(request, ["https://rp.example/after"])
    end

    test "an exactly-registered uri is honoured and state is appended", %{config: config} do
      {:ok, request} =
        EndSession.parse(config, %{
          "client_id" => @client_id,
          "post_logout_redirect_uri" => "https://rp.example/after",
          "state" => "xyz"
        })

      assert {:ok, url} = EndSession.confirm_redirect(request, ["https://rp.example/after"])
      assert url == "https://rp.example/after?state=xyz"
    end

    test "an unregistered uri is refused (no open redirect)", %{config: config} do
      {:ok, request} =
        EndSession.parse(config, %{
          "client_id" => @client_id,
          "post_logout_redirect_uri" => "https://evil.example/steal"
        })

      assert {:error, :invalid_post_logout_redirect_uri} =
               EndSession.confirm_redirect(request, ["https://rp.example/after"])
    end

    test "a requested uri with an empty registered list is refused", %{config: config} do
      {:ok, request} =
        EndSession.parse(config, %{"post_logout_redirect_uri" => "https://rp.example/after"})

      assert {:error, :invalid_post_logout_redirect_uri} = EndSession.confirm_redirect(request, [])
    end

    test "state merges into an existing query on the registered uri", %{config: config} do
      registered = "https://rp.example/after?theme=dark"

      {:ok, request} =
        EndSession.parse(config, %{
          "client_id" => @client_id,
          "post_logout_redirect_uri" => registered,
          "state" => "xyz"
        })

      assert {:ok, url} = EndSession.confirm_redirect(request, [registered])
      assert url =~ "theme=dark"
      assert url =~ "state=xyz"
    end
  end
end
