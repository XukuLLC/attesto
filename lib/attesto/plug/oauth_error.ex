if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.OAuthError do
    @moduledoc """
    Render the RFC 6750 / RFC 9449 error responses for the Attesto plugs.

    Translates the verifier's error atoms into the wire responses a
    protected resource owes a client:

      * `invalid_token` (RFC 6750 §3.1) - 401 with a `WWW-Authenticate`
        challenge for the scheme the request used (`Bearer` or `DPoP`).
      * `invalid_dpop_proof` (RFC 9449 §7.1) - 401 with a `DPoP`
        challenge, for a DPoP proof that failed verification.
      * `use_dpop_nonce` (RFC 9449 §8) - 401 with a `DPoP` challenge and a
        fresh `DPoP-Nonce` header, telling the client to retry with the
        nonce.
      * `insufficient_scope` (RFC 6750 §3.1) - 403 naming the required
        scope.

    Each helper sets the status, the `WWW-Authenticate` header (and
    `DPoP-Nonce` when relevant), writes a small JSON body, and halts the
    pipeline. Hosts may override only the transport details with `:send_error`,
    `:www_authenticate`, and `:no_store` callbacks; the OAuth error code,
    status, and challenge semantics remain owned here. This module is part of
    the optional `Attesto.Plug` layer; it only compiles when `Plug` is
    available.
    """

    import Plug.Conn

    @type scheme :: :bearer | :dpop

    @doc """
    Respond 401 with a `WWW-Authenticate` challenge for `scheme` carrying
    `error` (an OAuth error code string). Options: `:description`
    (`error_description`), `:dpop_nonce` (sets the `DPoP-Nonce` header, for
    `use_dpop_nonce`), and `:resource_metadata` (RFC 9728 §5.1: the URL of this
    resource's protected-resource metadata, advertised as a `resource_metadata`
    auth-param so the client can discover the authorization server). Halts.
    """
    @spec unauthorized(Plug.Conn.t(), scheme(), String.t(), keyword()) :: Plug.Conn.t()
    def unauthorized(conn, scheme, error, opts \\ []) do
      params = [{"error", error} | description_param(opts)] ++ resource_metadata_param(opts)

      conn
      |> maybe_put_dpop_nonce(Keyword.get(opts, :dpop_nonce))
      |> put_no_store(opts)
      |> put_www_authenticate(challenge(scheme, params), opts)
      |> send_error(401, error, opts)
    end

    @doc """
    Respond RFC 9470 §3 `insufficient_user_authentication` (401): the presented
    token does not meet the route's step-up requirement.

    `challenge` is the `Attesto.StepUp` challenge map carrying the `:acr_values`
    (space-delimited) and/or `:max_age` the client must re-request at the
    authorization endpoint; both are appended as `WWW-Authenticate` auth-params.
    This is an *authentication* error (401, like `invalid_token`), built on the
    same machinery as `unauthorized/4`, honoring the same `:description`,
    `:resource_metadata`, and `:send_error` / `:www_authenticate` / `:no_store`
    transport hooks. Halts.
    """
    @spec insufficient_user_authentication(Plug.Conn.t(), scheme(), map(), keyword()) :: Plug.Conn.t()
    def insufficient_user_authentication(conn, scheme, challenge, opts \\ []) when is_map(challenge) do
      description = Keyword.get(opts, :description, "requires a stronger or more recent authentication")

      params =
        [{"error", "insufficient_user_authentication"}, {"error_description", description}] ++
          step_up_params(challenge) ++ resource_metadata_param(opts)

      conn
      |> put_no_store(opts)
      |> put_www_authenticate(challenge(scheme, params), opts)
      |> send_error(401, "insufficient_user_authentication", Keyword.put(opts, :description, description))
    end

    # RFC 9470 §3: the unmet step-up dimensions, echoed so the client knows
    # exactly what to re-request. `acr_values` is already space-delimited; the
    # numeric `max_age` is stringified for the quoted-string auth-param.
    defp step_up_params(challenge) do
      []
      |> maybe_step_up_param("acr_values", Map.get(challenge, :acr_values))
      |> maybe_step_up_param("max_age", Map.get(challenge, :max_age))
    end

    defp maybe_step_up_param(params, _key, nil), do: params
    defp maybe_step_up_param(params, key, value), do: params ++ [{key, to_string(value)}]

    @doc """
    Respond 403 `insufficient_scope` naming the `required` scope list
    (RFC 6750 §3.1). The optional `opts` accepts `:resource_metadata` (RFC 9728
    §5.1: the URL of this resource's protected-resource metadata, advertised as
    a `resource_metadata` auth-param) and the SAME transport hooks
    `unauthorized/4` honors - `:send_error`, `:www_authenticate`, and
    `:no_store` - so a resource server can override the 403 response envelope and
    inject a per-conn challenge (e.g. a host-derived `resource_metadata` pointer)
    on the scope-rejection path too. The `insufficient_scope` error code, 403
    status, and the `error_description` / `scope` challenge semantics remain
    owned here. Halts.
    """
    @spec insufficient_scope(Plug.Conn.t(), [String.t()], scheme(), keyword()) :: Plug.Conn.t()
    def insufficient_scope(conn, required, scheme \\ :bearer, opts \\ [])

    # A keyword list in the `scheme` position is `opts` for the default Bearer
    # scheme: tolerate `insufficient_scope(conn, required, resource_metadata: url)`
    # so the RFC 9728 pointer is not silently dropped by the optional-arg order.
    def insufficient_scope(conn, required, opts, []) when is_list(opts) do
      insufficient_scope(conn, required, :bearer, opts)
    end

    def insufficient_scope(conn, required, scheme, opts) do
      scope = Enum.join(required, " ")
      description = "requires scope: #{scope}"

      params =
        [
          {"error", "insufficient_scope"},
          {"error_description", description},
          {"scope", scope}
        ] ++ resource_metadata_param(opts)

      # Thread the host transport hooks exactly as `unauthorized/4` does. The
      # `error_description` is owned here, so it is forced into `opts` before
      # `send_error` reads it (overriding any caller `:description`) - this keeps
      # the default JSON body identical while letting `:send_error` /
      # `:www_authenticate` / `:no_store` override the envelope and challenge.
      conn
      |> put_no_store(opts)
      |> put_www_authenticate(challenge(scheme, params), opts)
      |> send_error(403, "insufficient_scope", Keyword.put(opts, :description, description))
    end

    # ----- internal -----

    defp challenge(scheme, params) do
      scheme_label =
        case scheme do
          :dpop -> "DPoP"
          _ -> "Bearer"
        end

      param_str = Enum.map_join(params, ", ", fn {k, v} -> ~s(#{k}="#{escape(v)}") end)
      scheme_label <> " " <> param_str
    end

    defp description_param(opts) do
      case Keyword.get(opts, :description) do
        nil -> []
        desc -> [{"error_description", desc}]
      end
    end

    # RFC 9728 §5.1: a protected resource's `WWW-Authenticate` challenge MAY
    # carry a `resource_metadata` auth-param whose value is the URL of the
    # resource's protected-resource metadata, letting a client that received a
    # 401/403 discover which authorization server issues tokens for it. Quoted
    # like every other auth-param via `escape/1`. Omitted when no
    # `:resource_metadata` opt is present.
    defp resource_metadata_param(opts) do
      case Keyword.get(opts, :resource_metadata) do
        url when is_binary(url) ->
          # RFC 9728 §1.2 / §3: the pointer is an https metadata URL. Drop a
          # blank / non-https / malformed value rather than render an unusable
          # param or crash quoting a non-string. (The Phoenix layer validates
          # this at config build; this guards a core-only caller passing it
          # directly.) A loopback `http://` dev resource cannot use this static
          # value - by RFC 9728 the pointer is https - so a host that needs an
          # http loopback pointer in dev supplies the whole challenge via the
          # `:www_authenticate` hook, which bypasses this builder.
          if metadata_url?(url), do: [{"resource_metadata", url}], else: []

        _ ->
          []
      end
    end

    defp metadata_url?(url) do
      not Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, url) and
        match?(
          {:ok, %URI{scheme: "https", host: h, fragment: nil}} when is_binary(h) and h != "",
          URI.new(url)
        )
    end

    defp maybe_put_dpop_nonce(conn, nil), do: conn
    defp maybe_put_dpop_nonce(conn, nonce), do: put_resp_header(conn, "dpop-nonce", nonce)

    defp send_error(conn, status, error, opts) do
      body =
        %{"error" => error}
        |> maybe_put("error_description", Keyword.get(opts, :description))

      case Keyword.get(opts, :send_error) do
        fun when is_function(fun, 3) ->
          fun.(conn, status, body)

        {module, fun} when is_atom(module) and is_atom(fun) ->
          apply(module, fun, [conn, status, body])

        {module, fun, extra} when is_atom(module) and is_atom(fun) and is_list(extra) ->
          apply(module, fun, [conn, status, body | extra])

        _ ->
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(status, JSON.encode!(body))
          |> halt()
      end
    end

    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)

    defp put_www_authenticate(conn, challenge, opts) do
      case Keyword.get(opts, :www_authenticate) do
        fun when is_function(fun, 2) ->
          fun.(conn, challenge)

        {module, fun} when is_atom(module) and is_atom(fun) ->
          apply(module, fun, [conn, challenge])

        {module, fun, extra} when is_atom(module) and is_atom(fun) and is_list(extra) ->
          apply(module, fun, [conn, challenge | extra])

        _ ->
          put_resp_header(conn, "www-authenticate", challenge)
      end
    end

    defp put_no_store(conn, opts) do
      case Keyword.get(opts, :no_store) do
        fun when is_function(fun, 1) ->
          fun.(conn)

        {module, fun} when is_atom(module) and is_atom(fun) ->
          apply(module, fun, [conn])

        {module, fun, extra} when is_atom(module) and is_atom(fun) and is_list(extra) ->
          apply(module, fun, [conn | extra])

        _ ->
          conn
          |> put_resp_header("cache-control", "no-store")
          |> put_resp_header("pragma", "no-cache")
      end
    end

    # `WWW-Authenticate` auth-param values are quoted-strings; escape the
    # two characters that would break out of the quotes.
    defp escape(value) do
      value
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
    end
  end
else
  defmodule Attesto.Plug.OAuthError do
    @moduledoc "Requires the optional `:plug` dependency."

    @dep_error "Attesto.Plug.OAuthError requires the optional :plug dependency. " <>
                 "Add {:plug, \"~> 1.16\"} to your deps."

    def unauthorized(_conn, _scheme, _error, _opts \\ []), do: raise(@dep_error)

    def insufficient_user_authentication(_conn, _scheme, _challenge, _opts \\ []), do: raise(@dep_error)

    def insufficient_scope(_conn, _required, _scheme \\ :bearer, _opts \\ []), do: raise(@dep_error)
  end
end
