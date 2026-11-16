defmodule Attesto.Plug.PrincipalUnavailableTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias Attesto.Plug.ResourceAuthenticate

  test "principal outage uses exactly one outcome hook and a neutral 503" do
    owner = self()

    response =
      authenticate(fn _, _ -> {:error, {:temporarily_unavailable, "private-reason"}} end,
        principal_unavailable_send_error: renderer(owner, :principal_unavailable),
        policy_rejection_send_error: renderer(owner, :policy_rejected),
        send_error: renderer(owner, :verifier_unavailable)
      )

    assert response.halted
    assert response.status == 503
    assert JSON.decode!(response.resp_body) == %{"error" => "temporarily_unavailable"}
    assert get_resp_header(response, "www-authenticate") == []
    assert get_resp_header(response, "retry-after") == []
    assert get_resp_header(response, "cache-control") == ["no-store"]
    refute Map.has_key?(response.assigns, :attesto_principal)
    refute Map.has_key?(response.assigns, :attesto_context)
    assert_receive {:outcome, :principal_unavailable, 503, %{"error" => "temporarily_unavailable"}}
    refute_receive {:outcome, _, _, _}
  end

  test "outage falls back to the ordinary error renderer" do
    response = authenticate(fn _, _ -> {:error, {:temporarily_unavailable, %{private: "reason"}}} end)
    assert response.status == 503
    assert JSON.decode!(response.resp_body) == %{"error" => "temporarily_unavailable"}
  end

  for result <- [
        {:error, :temporarily_unavailable},
        {:error, {:temporarily_unavailable}},
        {:error, {:temporarily_unavailable, :reason, :extra}},
        :temporarily_unavailable
      ] do
    test "malformed outage #{inspect(result)} remains a policy refusal" do
      response =
        authenticate(fn _, _ -> unquote(Macro.escape(result)) end,
          policy_rejection_send_error: renderer(self(), :policy_rejected)
        )

      assert response.halted
      assert response.status == 401
      assert JSON.decode!(response.resp_body) == %{"error" => "invalid_token"}
      assert_receive {:outcome, :policy_rejected, 401, %{"error" => "invalid_token"}}
      refute_receive {:outcome, _, _, _}
    end
  end

  test "a raised callback exception reaches the host, as from the verifier" do
    assert_raise RuntimeError, "private-exception", fn ->
      authenticate(fn _, _ -> raise "private-exception" end)
    end
  end

  test "successful principal resolution still assigns context" do
    response = authenticate(fn _, _ -> {:ok, :principal} end)
    refute response.halted
    assert response.assigns.attesto_context.principal == :principal
  end

  defp authenticate(principal, extra \\ []) do
    opts =
      ResourceAuthenticate.init(
        [
          config: :remote,
          resource_audience: "https://api.example/resource",
          verify: fn _, _, _ -> {:ok, %{"sub" => "private-subject"}} end,
          principal: principal
        ] ++ extra
      )

    conn(:get, "/resource")
    |> put_req_header("authorization", "Bearer private-token")
    |> ResourceAuthenticate.call(opts)
  end

  defp renderer(owner, outcome) do
    fn conn, status, body ->
      send(owner, {:outcome, outcome, status, body})
      conn |> send_resp(status, JSON.encode!(body)) |> halt()
    end
  end
end
