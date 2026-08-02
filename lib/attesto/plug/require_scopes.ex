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
      * `:send_error`, `:www_authenticate`, `:no_store` - the transport hooks
        `Attesto.Plug.OAuthError` honors, threaded onto BOTH the 403 and the 401
        this plug renders so a host can override the response envelope and inject
        a per-conn challenge (e.g. a request-derived `resource_metadata` pointer)
        on the scope-rejection path, not just the authentication-rejection path.

    A request that reaches this plug without verified claims (the
    authentication plug did not run or did not assign them) is treated as
    unauthenticated and answered 401.

    Part of the optional `Attesto.Plug` layer; compiles only with `Plug`.
    """

    @behaviour Plug

    alias Attesto.Plug.OAuthError
    alias Attesto.Scope

    @default_claims_key :attesto_claims

    @transport_keys [:send_error, :www_authenticate, :no_store]

    @impl Plug
    def init(scopes) when is_list(scopes) do
      {required, claims_key, resource_metadata, transport} = normalize(scopes)

      if required == [] do
        raise ArgumentError,
              "Attesto.Plug.RequireScopes requires a non-empty list of scopes; an endpoint " <>
                "must declare what it requires."
      end

      %{
        required: required,
        catalog: Scope.new_catalog(required),
        claims_key: claims_key,
        resource_metadata: resource_metadata,
        transport: transport
      }
    end

    @impl Plug
    def call(conn, %{
          required: required,
          catalog: catalog,
          claims_key: claims_key,
          resource_metadata: resource_metadata,
          transport: transport
        }) do
      case conn.assigns[claims_key] do
        %{"scope" => scope} = claims when is_binary(scope) ->
          granted = Scope.parse(scope, whitespace: :ascii_whitespace)

          if Scope.grants_all?(catalog, granted, required),
            do: conn,
            else:
              OAuthError.insufficient_scope(
                conn,
                required,
                scheme_of(claims),
                error_opts(resource_metadata, transport)
              )

        %{} = claims ->
          # Authenticated but no scope claim: cannot satisfy any requirement.
          OAuthError.insufficient_scope(
            conn,
            required,
            scheme_of(claims),
            error_opts(resource_metadata, transport)
          )

        _ ->
          OAuthError.unauthorized(
            conn,
            :bearer,
            "invalid_token",
            error_opts(resource_metadata, transport, description: "request is not authenticated")
          )
      end
    end

    # Build the OAuthError opts: the host transport hooks (`:send_error`,
    # `:www_authenticate`, `:no_store`) carried verbatim, plus the RFC 9728 §5.1
    # `resource_metadata` pointer (when set) and any extra (e.g. `:description`).
    defp error_opts(resource_metadata, transport, extra \\ []) do
      transport
      |> maybe_put_resource_metadata(resource_metadata)
      |> Keyword.merge(extra)
    end

    defp maybe_put_resource_metadata(opts, nil), do: opts
    defp maybe_put_resource_metadata(opts, url), do: Keyword.put(opts, :resource_metadata, url)

    # The challenge scheme must match how the client authenticated (RFC
    # 9449 §7.1): a DPoP-bound token carries a `cnf.jkt`, so its
    # insufficient_scope challenge is a `DPoP` challenge, not `Bearer`. A
    # bearer or mTLS-bound token (no `cnf.jkt`) gets the `Bearer` challenge.
    defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
    defp scheme_of(_claims), do: :bearer

    defp normalize(scopes) do
      if Keyword.keyword?(scopes) and scopes != [] do
        {Keyword.get(scopes, :scopes, []), Keyword.get(scopes, :claims_key, @default_claims_key),
         Keyword.get(scopes, :resource_metadata), Keyword.take(scopes, @transport_keys)}
      else
        {scopes, @default_claims_key, nil, []}
      end
    end
  end
end
