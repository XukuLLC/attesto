if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.RequireScopes do
    @moduledoc """
    Authorize a request against the scopes on the verified token.

    Runs after `Attesto.Plug.Authenticate` (which assigns the verified
    claims): it reads the `scope` claim, splits it, and checks that the
    granted set covers every required scope via `Attesto.Scope`. On
    success the conn passes through; otherwise it answers 403
    `insufficient_scope` (RFC 6750 §3.1).

        plug Attesto.Plug.RequireScopes, ["documents.read"]

    Options. The first argument may be a bare list of required scopes, or a
    keyword list with:

      * `:scopes` (required) - the list of required concrete scopes.
      * `:claims_key` - the `conn.assigns` key the claims were put under
        (default `:attesto_claims`, matching `Attesto.Plug.Authenticate`).
      * `:resource_metadata` - the URL of this resource's protected-resource
        metadata (RFC 9728), advertised as a `resource_metadata` auth-param on
        the 403 `insufficient_scope` (and the 401 `invalid_token` for an
        unauthenticated request) `WWW-Authenticate` challenge (RFC 9728 §5.1).

    A request that reaches this plug without verified claims (the
    authentication plug did not run or did not assign them) is treated as
    unauthenticated and answered 401.

    Part of the optional `Attesto.Plug` layer; compiles only with `Plug`.
    """

    @behaviour Plug

    alias Attesto.Plug.OAuthError
    alias Attesto.Scope

    @default_claims_key :attesto_claims

    @impl Plug
    def init(scopes) when is_list(scopes) do
      {required, claims_key, resource_metadata} = normalize(scopes)

      if required == [] do
        raise ArgumentError,
              "Attesto.Plug.RequireScopes requires a non-empty list of scopes; an endpoint " <>
                "must declare what it requires."
      end

      %{
        required: required,
        catalog: Scope.new_catalog(required),
        claims_key: claims_key,
        resource_metadata: resource_metadata
      }
    end

    @impl Plug
    def call(conn, %{required: required, catalog: catalog, claims_key: claims_key, resource_metadata: resource_metadata}) do
      case conn.assigns[claims_key] do
        %{"scope" => scope} = claims when is_binary(scope) ->
          granted = String.split(scope, ~r/\s+/, trim: true)

          if Scope.grants_all?(catalog, granted, required),
            do: conn,
            else: OAuthError.insufficient_scope(conn, required, scheme_of(claims), error_opts(resource_metadata))

        %{} = claims ->
          # Authenticated but no scope claim: cannot satisfy any requirement.
          OAuthError.insufficient_scope(conn, required, scheme_of(claims), error_opts(resource_metadata))

        _ ->
          OAuthError.unauthorized(
            conn,
            :bearer,
            "invalid_token",
            error_opts(resource_metadata, description: "request is not authenticated")
          )
      end
    end

    # RFC 9728 §5.1: thread the configured `resource_metadata` pointer (when set)
    # into the OAuthError challenge so the 403/401 carries it.
    defp error_opts(nil), do: []
    defp error_opts(url), do: [resource_metadata: url]
    defp error_opts(nil, extra), do: extra
    defp error_opts(url, extra), do: [{:resource_metadata, url} | extra]

    # The challenge scheme must match how the client authenticated (RFC
    # 9449 §7.1): a DPoP-bound token carries a `cnf.jkt`, so its
    # insufficient_scope challenge is a `DPoP` challenge, not `Bearer`. A
    # bearer or mTLS-bound token (no `cnf.jkt`) gets the `Bearer` challenge.
    defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
    defp scheme_of(_claims), do: :bearer

    defp normalize(scopes) do
      if Keyword.keyword?(scopes) and scopes != [] do
        {Keyword.get(scopes, :scopes, []), Keyword.get(scopes, :claims_key, @default_claims_key),
         Keyword.get(scopes, :resource_metadata)}
      else
        {scopes, @default_claims_key, nil}
      end
    end
  end
end
