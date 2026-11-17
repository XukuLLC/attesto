if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.ProtectResource do
    @moduledoc """
    Authenticate and authorize one OAuth protected resource in order.

        plug Attesto.Plug.ProtectResource,
          config: {MyHost.Auth, :config},
          resource_path: "/documents",
          base_url: "https://api.example.com",
          resource_audience: :resource,
          scopes: ["documents.read"],
          principal: {MyHost.Auth, :load_principal}

    All `Attesto.Plug.ResourceAuthenticate` options are accepted. `:scope` or
    `:scopes` supplies the required concrete scopes; `:scope_hierarchy` supplies
    the host's broader-to-narrower scope map. Transport hooks and assign keys
    are shared between authentication and authorization.

    Use `prepare/1`, `authenticate/2` and `authorize/3` when a bounded,
    side-effect-free classification determines operation scopes after verifying
    the token. An empty dynamic list still requires authentication by the same
    prepared boundary. A prepared split boundary cannot be used with `call/2`.

    `init/2` and `prepare/2` additionally accept `:authenticate` and
    `:require_scopes` Plug modules for protocol adapters. They must preserve the
    core option and verified-assignment contracts. Normal hosts use the defaults.
    Initialization produces no closures and works in compile-time pipelines.
    """

    @behaviour Plug

    alias Attesto.Plug.OAuthError
    alias Attesto.Plug.ResourceAuthenticate, as: Authenticate
    alias Attesto.Plug.ResourceScopes, as: RequireScopes
    alias Attesto.ResourceContext, as: Auth
    alias Attesto.Scope

    @boundary_private_key :attesto_protect_resource_boundary

    @typedoc "An opaque, prepared protected-resource boundary."
    @opaque protection :: %{
              required(:authenticate) => keyword(),
              required(:authenticate_module) => module(),
              required(:scopes_module) => module(),
              required(:boundary_id) => binary(),
              required(:require_scopes) => nil,
              required(:scope_opts) => keyword()
            }

    # Options that RequireScopes consumes. The scope set is its own; the rest are
    # shared with Authenticate so both steps render through one error envelope and
    # read the same assigns.
    @scope_keys [:scope, :scopes]
    @shared_keys [
      :send_error,
      :www_authenticate,
      :no_store,
      :resource_metadata,
      :challenge_scopes,
      :allow_http,
      :claims_key,
      :scopes_key,
      :scope_hierarchy
    ]

    @impl Plug
    def init(opts), do: init(opts, [])

    @doc "Initialize protection with optional authentication and scope plug adapters."
    def init(opts, adapters) when is_list(opts) do
      protection = build_protection(opts, adapters)

      Map.put(
        protection,
        :require_scopes,
        protection.scopes_module.init(Keyword.merge(protection.scope_opts, Keyword.take(opts, @scope_keys)))
      )
    end

    @impl Plug
    def call(_conn, %{require_scopes: nil}) do
      raise ArgumentError,
            "a split ProtectResource boundary must call authenticate/2 and authorize/3 explicitly"
    end

    def call(conn, %{require_scopes: require_scopes} = protection) do
      conn = authenticate(conn, protection)

      if conn.halted do
        conn
      else
        protection.scopes_module.call(conn, require_scopes)
      end
    end

    @doc "Prepares an authentication-first boundary whose scopes are supplied to `authorize/3`."
    @spec prepare(keyword()) :: protection()
    def prepare(opts), do: prepare(opts, [])

    @doc "Prepare a split boundary with optional authentication and scope plug adapters."
    def prepare(opts, adapters) when is_list(opts) do
      if Enum.any?(@scope_keys, &Keyword.has_key?(opts, &1)) do
        raise ArgumentError,
              "prepare/1 accepts dynamic scopes only; pass the required scopes to authorize/3"
      end

      opts
      |> build_protection(adapters)
      |> Map.put(:boundary_id, :crypto.strong_rand_bytes(32))
    end

    defp build_protection(opts, adapters) do
      authenticate_module = Keyword.get(adapters, :authenticate, Authenticate)
      scopes_module = Keyword.get(adapters, :require_scopes, RequireScopes)
      authenticate = authenticate_module.init(authenticate_opts(opts))

      scope_opts =
        authenticate
        |> Keyword.take(@shared_keys)
        |> Keyword.merge(Keyword.take(opts, [:scope_hierarchy]))

      %{
        authenticate: authenticate,
        authenticate_module: authenticate_module,
        scopes_module: scopes_module,
        require_scopes: nil,
        scope_opts: scope_opts
      }
    end

    @doc "Authenticates a request through a prepared ProtectResource boundary."
    @spec authenticate(Plug.Conn.t(), protection() | map()) :: Plug.Conn.t()
    def authenticate(conn, %{authenticate: authenticate} = protection) do
      conn =
        conn
        |> Plug.Conn.put_private(@boundary_private_key, nil)
        |> protection.authenticate_module.call(authenticate)

      if conn.halted do
        conn
      else
        mark_boundary_authenticated(conn, protection)
      end
    end

    @doc "Enforces dynamically selected scopes after `authenticate/2` and before dispatch."
    @spec authorize(Plug.Conn.t(), protection(), [String.t()]) :: Plug.Conn.t()
    def authorize(conn, protection, scopes) when is_list(scopes) do
      validate_dynamic_scopes!(scopes)

      cond do
        conn.halted ->
          conn

        not boundary_authenticated?(conn, protection) ->
          reject_unbound_connection(conn, protection)

        scopes == [] ->
          conn

        true ->
          require_scopes =
            protection.scope_opts
            |> Keyword.put(:scopes, scopes)
            |> protection.scopes_module.init()

          protection.scopes_module.call(conn, require_scopes)
      end
    end

    def authorize(_conn, _protection, _scopes) do
      raise ArgumentError, "dynamic scopes must be unique RFC 6749 scope-token strings"
    end

    defp validate_dynamic_scopes!(scopes) do
      if not Scope.valid_list?(scopes) or Enum.uniq(scopes) != scopes do
        raise ArgumentError, "dynamic scopes must be unique RFC 6749 scope-token strings"
      end
    end

    defp authenticate_opts(opts) do
      opts
      |> Keyword.drop(@scope_keys ++ [:scope_hierarchy])
    end

    defp mark_boundary_authenticated(conn, %{boundary_id: boundary_id}) when is_binary(boundary_id),
      do: Plug.Conn.put_private(conn, @boundary_private_key, boundary_id)

    defp mark_boundary_authenticated(conn, _protection), do: conn

    defp boundary_authenticated?(conn, %{boundary_id: boundary_id}) when is_binary(boundary_id),
      do: conn.private[@boundary_private_key] == boundary_id

    defp boundary_authenticated?(_conn, _protection), do: false

    defp reject_unbound_connection(conn, protection) do
      claims_key = Keyword.get(protection.scope_opts, :claims_key, :attesto_claims)

      transport =
        protection.scope_opts
        |> Authenticate.oauth_error_opts()

      OAuthError.unauthorized(
        conn,
        Auth.scheme(conn.assigns[claims_key]),
        "invalid_token",
        Keyword.put(transport, :description, "request was not authenticated by this protected-resource boundary")
      )
    end
  end
end
