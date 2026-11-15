if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.ResourceScopes do
    @moduledoc """
    Check the verified scope list assigned by `Attesto.Plug.ResourceAuthenticate`.

    Accepts a bare scope list or `:scope` / `:scopes`, plus `:scope_hierarchy`.
    Requirements must be unique concrete RFC 6749 scope tokens. `:claims_key`
    defaults to `:attesto_claims` and `:scopes_key` to `:attesto_scopes`.
    `:send_error`, `:www_authenticate`, `:no_store`, `:resource_metadata` and
    `:allow_http` pass to `Attesto.Plug.OAuthError`. A challenge lists every
    required operation scope; a granted broader scope can satisfy a hierarchy.
    """

    @behaviour Plug

    alias Attesto.Plug.OAuthError
    alias Attesto.ResourceContext, as: Auth
    alias Attesto.Scope

    @claims_key :attesto_claims
    @scopes_key :attesto_scopes

    @impl Plug
    def init(opts) when is_list(opts) do
      keyword_opts = if Keyword.keyword?(opts), do: opts, else: []

      if Keyword.has_key?(keyword_opts, :scope) and Keyword.has_key?(keyword_opts, :scopes) do
        raise ArgumentError, "use either :scope or :scopes, not both"
      end

      required = normalize_required(opts)

      if required == [] or not Scope.valid_list?(required) or Enum.uniq(required) != required do
        raise ArgumentError,
              "Attesto.Plug.ResourceScopes requires unique RFC 6749 scope-token strings"
      end

      hierarchy = Keyword.get(keyword_opts, :scope_hierarchy, %{})
      catalog = Scope.new_catalog(required, hierarchy: hierarchy)

      if Enum.any?(required, &String.contains?(&1, "*")) or
           !Enum.all?(required, &Scope.known?(catalog, &1)) do
        raise ArgumentError,
              "Attesto.Plug.ResourceScopes requires concrete scopes; wildcard requirements are forbidden"
      end

      %{
        catalog: catalog,
        claims_key: Keyword.get(keyword_opts, :claims_key, @claims_key),
        required: required,
        scopes_key: Keyword.get(keyword_opts, :scopes_key, @scopes_key),
        transport:
          keyword_opts
          |> Keyword.take([:send_error, :www_authenticate, :no_store, :resource_metadata, :allow_http])
      }
    end

    @impl Plug
    def call(conn, opts) do
      granted = Map.get(conn.assigns, opts.scopes_key)

      cond do
        is_list(granted) and Scope.grants_all?(opts.catalog, granted, opts.required) ->
          conn

        is_list(granted) ->
          OAuthError.insufficient_scope(
            conn,
            opts.required,
            Auth.scheme(conn.assigns[opts.claims_key]),
            opts.transport
          )

        true ->
          OAuthError.unauthorized(
            conn,
            :bearer,
            "invalid_token",
            Keyword.put(opts.transport, :description, "request is not authenticated")
          )
      end
    end

    defp normalize_required(opts) do
      cond do
        Keyword.keyword?(opts) and Keyword.has_key?(opts, :scope) ->
          [Keyword.fetch!(opts, :scope)]

        Keyword.keyword?(opts) ->
          List.wrap(Keyword.get(opts, :scopes, []))

        true ->
          List.wrap(opts)
      end
    end
  end
end
