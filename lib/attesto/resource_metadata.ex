if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.ResourceMetadata do
    @moduledoc """
    Builders for OAuth metadata for individual protected resources.

    Protected resources publish RFC 9728 documents pointing clients to their
    RFC 8414 authorization servers. Supply each resource's `:scopes_supported`
    and `:bearer_methods_supported` explicitly; no scope catalog is assumed.

    ## Origin pinning behind a proxy

    The `resource` identifier identifies this server, while
    `authorization_servers` identifies the issuer a client must use to obtain a
    token. A resource identifier may be derived from the live connection when it
    is used only for discovery. Any authentication policy that derives its token
    audience from the resource identifier must pin the origin.

    Behind a TLS-terminating reverse proxy that derivation is both fragile and a
    spoofing vector: `conn.scheme` is often `http`, and `conn.host` reflects the
    request `Host` or whatever `X-Forwarded-*` rewriting produced. An attacker
    can therefore influence an unpinned `resource`. Pin the resource origin when
    it drives authorization policy, and identify the authorization server from a
    trusted configuration source:

      * The **`resource`** identifier and the well-known metadata URL use
        `resolve_origin/2` - the *resource server* origin, pinned via `:base_url`
        or `:origin` (a `String.t()`, a `(Plug.Conn.t() -> String.t())` callback,
        or a `{module, fun}` / `{module, fun, args}` tuple), falling back to the
        live request origin only when neither option is present. An explicitly
        configured pin that is invalid raises instead of falling back.
      * **`authorization_servers`** defaults to the `:config` issuer (or an
        explicit `:issuer` string) when one is supplied - the authorization server
        the host already trusts for token verification, advertised verbatim - and
        otherwise must be supplied explicitly with `:authorization_servers`.
        The issuer is deliberately NOT used as the `resource` origin: RFC 9728
        keeps the protected resource and its authorization server distinct, and
        in a FAPI deployment they are usually different hosts.

    Either can still be overridden outright with an explicit `:resource` /
    `:authorization_servers` opt. Use the same pin on discovery and authentication.
    """

    alias Attesto.Config
    alias Attesto.Discovery
    alias Attesto.DPoP
    alias Attesto.Plug.Authenticate
    alias Attesto.ProtectedResourceMetadata
    alias Attesto.ResourceContext, as: Auth
    alias Attesto.URI, as: AttestoURI

    @doc """
    Build an RFC 9728 protected-resource metadata document.

    Required options:

      * `:resource` - an absolute HTTPS protected resource identifier with no
        fragment, usually the canonical resource URI such as
        `"https://mcp.example.com/mcp"`. Pass `allow_http: true` for a deliberate
        local development endpoint.
      * `:authorization_servers` - a non-empty, unique list of HTTPS issuer
        identifiers with no query or fragment.

    Common options include `:scopes_supported`, `:bearer_methods_supported`,
    `:dpop_signing_alg_values_supported`, and
    `:tls_client_certificate_bound_access_tokens`.

    `:dpop_signing_alg_values_supported` defaults to every DPoP algorithm
    Attesto verifies. A resource that accepts only Bearer tokens passes `false`
    (or `[]`) to leave the member out of the document; RFC 9728 §3.2 does not
    allow publishing it as an empty array.

    Pass `:authenticate` with the option list given to
    `Attesto.Plug.ProtectResource` (or `Attesto.Plug.ResourceAuthenticate`) to have
    that default follow the plug: when those options cannot accept a DPoP request
    (`Attesto.Plug.Authenticate.accepts_dpop?/1`), the member is left out. An
    explicit `:dpop_signing_alg_values_supported` takes precedence.
    """
    @spec protected_resource(keyword()) :: %{required(String.t()) => term()}
    def protected_resource(opts) when is_list(opts) do
      _resource = Keyword.fetch!(opts, :resource)
      authorization_servers = Keyword.fetch!(opts, :authorization_servers)

      validate_authorization_servers!(authorization_servers)

      opts
      |> put_dpop_signing_algs()
      |> ProtectedResourceMetadata.metadata()
    end

    @doc """
    Build protected-resource metadata from a Plug connection and resource path.

    `resource_path` is the path of the protected endpoint, for example `"/mcp"` or
    `"/mcp/admin"`. The `resource` identifier is `resolve_origin/2` (the resource
    server origin, pinned via `:base_url`/`:origin`) joined with that path.
    `:authorization_servers` defaults to the `:config` issuer (or an explicit
    `:issuer` string) when one is given. One of those sources is required; the
    authorization server is never inferred from the request authority.

    An explicit `:resource` or `:authorization_servers` opt overrides the derived
    value, and short-circuits its derivation: a pinned origin / issuer callback is
    not invoked (and cannot fail) for a value the host supplied outright.
    """
    @spec protected_resource(Plug.Conn.t(), String.t(), keyword()) :: %{required(String.t()) => term()}
    def protected_resource(%Plug.Conn{} = conn, resource_path, opts \\ []) when is_binary(resource_path) do
      validate_metadata_options!(opts)

      derive_resource? = not Keyword.has_key?(opts, :resource)
      derive_servers? = not Keyword.has_key?(opts, :authorization_servers)
      issuer = if derive_servers?, do: configured_issuer!(opts)

      # Resolve the resource origin AT MOST ONCE, and only when `resource` needs
      # derivation. The authorization server has its own mandatory trust source
      # and never comes from this request-derived value.
      origin = if derive_resource?, do: resolve_origin(conn, opts)

      opts
      |> maybe_put(derive_resource?, :resource, fn -> origin <> normalize_resource_path!(resource_path) end)
      |> maybe_put(derive_servers?, :authorization_servers, fn -> [issuer] end)
      |> Keyword.drop([:base_url, :origin, :issuer, :config])
      |> protected_resource()
    end

    @doc """
    Build the well-known metadata URL for an protected resource path.

        iex> Attesto.ResourceMetadata.protected_resource_url("https://mcp.example.com", "/mcp")
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

    A Plug connection can also be passed as the first argument. The legacy
    two-argument connection form remains available; new code should pass an
    options list as the third argument so origin pinning is explicit.
    """
    @spec protected_resource_url(String.t(), String.t()) :: String.t()
    def protected_resource_url(base_url, resource_path) when is_binary(base_url) and is_binary(resource_path) do
      String.trim_trailing(base_url, "/") <> protected_resource_metadata_path(resource_path)
    end

    @spec protected_resource_url(Plug.Conn.t(), String.t()) :: String.t()
    def protected_resource_url(%Plug.Conn{} = conn, resource_path) when is_binary(resource_path) do
      protected_resource_url(conn, resource_path, [])
    end

    @doc """
    Build the well-known metadata URL, resolving the origin via `resolve_origin/2`.

    Pass `:base_url`/`:origin` in `opts` to pin the resource origin (so the
    challenge URL matches a pinned `resource`); with no such opt the live request
    origin is used.
    """
    @spec protected_resource_url(Plug.Conn.t(), String.t(), keyword()) :: String.t()
    def protected_resource_url(%Plug.Conn{} = conn, resource_path, opts)
        when is_binary(resource_path) and is_list(opts) do
      conn
      |> resolve_origin(opts)
      |> protected_resource_url(resource_path)
    end

    @doc """
    Resolve the *resource server* origin used to build the `resource` identifier
    and the well-known metadata URL.

    This is the protected resource's own origin (RFC 9728 `resource`), which is
    distinct from the authorization server (`authorization_servers` / the
    `Attesto.Config` issuer) - the two are often different hosts in a FAPI
    deployment, so the issuer is NOT used here. Precedence:

      1. an explicit `:base_url` or `:origin` opt - a `String.t()`, a
         `(Plug.Conn.t() -> String.t())` callback, or a `{module, fun}` /
         `{module, fun, args}` tuple (the conn is prepended to `args`), resolved
         at request time;
      2. the live request origin (`conn.scheme`/`conn.host`/`conn.port`).

    When neither pin is present, the request origin is used. Once either option is
    present, it is configuration: invalid literal values and invalid callback
    results raise instead of falling back to the request authority. A trailing
    slash is trimmed so the result joins cleanly with a resource path.
    """
    @spec resolve_origin(Plug.Conn.t(), keyword()) :: String.t()
    def resolve_origin(%Plug.Conn{} = conn, opts) when is_list(opts) do
      case origin_spec(opts) do
        :none -> base_url(conn)
        {:configured, key, spec} -> resolve_pinned_origin!(key, spec, conn, opts)
      end
    end

    @doc "Shared protected-resource metadata helper."
    @spec validate_origin_options!(keyword()) :: :ok
    def validate_origin_options!(opts) when is_list(opts) do
      Enum.each([:base_url, :origin], fn key ->
        if Keyword.has_key?(opts, key), do: validate_origin_spec!(key, Keyword.fetch!(opts, key), opts)
      end)

      :ok
    end

    @doc "Shared protected-resource metadata helper."
    @spec require_pinned_origin!(keyword()) :: :ok
    def require_pinned_origin!(opts) when is_list(opts) do
      validate_origin_options!(opts)

      if Enum.any?([:base_url, :origin], &Keyword.has_key?(opts, &1)) do
        :ok
      else
        raise ArgumentError,
              "resource_audience: :resource requires a pinned :base_url or :origin; " <>
                "the request Host cannot define an access-token audience"
      end
    end

    @doc "Shared protected-resource metadata helper."
    @spec validate_metadata_options!(keyword()) :: :ok
    def validate_metadata_options!(opts) when is_list(opts) do
      validate_origin_options!(opts)

      if !Enum.any?([:authorization_servers, :issuer, :config], &Keyword.has_key?(opts, &1)) do
        raise ArgumentError,
              "protected-resource metadata requires :authorization_servers, :issuer, or :config; " <>
                "the request Host cannot define the authorization server"
      end

      case Keyword.fetch(opts, :authorization_servers) do
        {:ok, servers} -> validate_authorization_servers!(servers)
        :error -> validate_authorization_source!(opts)
      end

      :ok
    end

    @doc """
    The canonical RFC 8707 / RFC 9728 resource identifier for this protected
    resource: the resolved origin joined with the resource path (for example
    `"https://mcp.example.com/mcp"`).

    This is the SINGLE source for the value that must agree across the chain — the
    RFC 9728 metadata `resource` field, the RFC 8707 `resource` a client requests,
    the `aud` the authorization server mints, and the audience the resource-server
    plug validates. Driving the audience check and the advertised metadata from
    this one function is what makes them consistent by construction (a host cannot
    configure them into disagreement). Origin precedence is `resolve_origin/2`'s.
    """
    @spec resource_identifier(Plug.Conn.t(), String.t(), keyword()) :: String.t()
    def resource_identifier(%Plug.Conn{} = conn, resource_path, opts \\ []) when is_binary(resource_path) do
      resolve_origin(conn, opts) <> normalize_resource_path!(resource_path)
    end

    @doc "Shared protected-resource metadata helper."

    @spec resource_metadata_param(String.t()) :: String.t()
    def resource_metadata_param(url) when is_binary(url), do: ~s(resource_metadata="#{escape(url)}")

    @doc "Shared protected-resource metadata helper."

    @spec append_resource_metadata(String.t(), String.t()) :: String.t()
    def append_resource_metadata(challenge, url) when is_binary(challenge) and is_binary(url) do
      challenge <> ", " <> resource_metadata_param(url)
    end

    @doc "Shared protected-resource metadata helper."

    @spec authorization_server(Config.t(), keyword()) :: %{required(String.t()) => term()}
    def authorization_server(%Config{} = config, opts \\ []), do: Discovery.metadata(config, opts)

    @doc "Shared protected-resource metadata helper."
    @spec normalize_resource_path!(term(), keyword()) :: String.t()
    def normalize_resource_path!(resource_path, opts \\ [])

    def normalize_resource_path!(resource_path, opts) when is_binary(resource_path) and is_list(opts) do
      normalized = if String.starts_with?(resource_path, "/"), do: resource_path, else: "/" <> resource_path
      allow_root? = Keyword.get(opts, :allow_root, true)

      invalid? =
        not String.valid?(normalized) or
          String.contains?(normalized, ["?", "#"]) or
          Enum.any?(String.split(normalized, "/"), &(&1 in [".", ".."])) or
          (not allow_root? and normalized == "/")

      if invalid? do
        raise ArgumentError,
              "resource_path must be a plain#{if allow_root?, do: "", else: " non-root"} path without dot segments, query, or fragment"
      end

      normalized
    end

    def normalize_resource_path!(_resource_path, _opts), do: raise(ArgumentError, "resource_path must be a string")

    @doc "Shared protected-resource metadata helper."
    @spec protected_resource_metadata_path(String.t()) :: String.t()
    def protected_resource_metadata_path(resource_path) do
      resource_path
      |> normalize_resource_path!()
      |> ProtectedResourceMetadata.well_known_path()
    end

    # An absent or `nil` option publishes every algorithm Attesto verifies. An
    # explicit `false` or `[]` is the host saying this resource takes no DPoP
    # proofs, so the member is left out (RFC 9728 §3.2: a parameter with zero
    # values MUST be omitted).
    defp put_dpop_signing_algs(opts) do
      {authenticate, opts} = Keyword.pop(opts, :authenticate)

      case Keyword.get(opts, :dpop_signing_alg_values_supported) do
        nil -> put_default_dpop_signing_algs(opts, authenticate)
        omit when omit in [false, []] -> Keyword.delete(opts, :dpop_signing_alg_values_supported)
        _algs -> opts
      end
    end

    # With no `:authenticate` options the default list is published, as before.
    # With them, the default follows what the plug accepts.
    defp put_default_dpop_signing_algs(opts, authenticate) do
      if is_nil(authenticate) or Authenticate.accepts_dpop?(authenticate) do
        Keyword.put(opts, :dpop_signing_alg_values_supported, DPoP.allowed_algs())
      else
        Keyword.delete(opts, :dpop_signing_alg_values_supported)
      end
    end

    # Put a derived value only when the caller asked for derivation; the value
    # `fun` is invoked lazily, so an explicit `:resource` / `:authorization_servers`
    # short-circuits its (possibly callback-bearing, possibly failing) derivation.
    defp maybe_put(opts, false, _key, _fun), do: opts
    defp maybe_put(opts, true, key, fun), do: Keyword.put(opts, key, fun.())

    @doc "Shared protected-resource metadata helper."
    @spec static_pin?(keyword()) :: boolean()
    def static_pin?(opts) when is_list(opts) do
      is_binary(Keyword.get(opts, :resource)) or
        case origin_spec(opts) do
          {:configured, _key, spec} -> is_binary(spec)
          :none -> false
        end
    end

    defp escape(value) do
      value
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
    end

    defp origin_spec(opts) do
      cond do
        Keyword.has_key?(opts, :base_url) -> {:configured, :base_url, Keyword.fetch!(opts, :base_url)}
        Keyword.has_key?(opts, :origin) -> {:configured, :origin, Keyword.fetch!(opts, :origin)}
        true -> :none
      end
    end

    defp resolve_pinned_origin!(key, spec, conn, opts) do
      resolved = if is_binary(spec), do: spec, else: Auth.invoke(spec, [conn])

      case resolved do
        url when is_binary(url) -> validate_origin_value!(key, url, opts)
        _ -> raise_invalid_origin!(key)
      end
    end

    defp validate_origin_spec!(key, url, opts) when is_binary(url), do: validate_origin_value!(key, url, opts)
    defp validate_origin_spec!(_key, fun, _opts) when is_function(fun, 1), do: :ok

    defp validate_origin_spec!(_key, {module, fun}, _opts) when is_atom(module) and is_atom(fun), do: :ok

    defp validate_origin_spec!(_key, {module, fun, args}, _opts)
         when is_atom(module) and is_atom(fun) and is_list(args), do: :ok

    defp validate_origin_spec!(key, _spec, _opts), do: raise_invalid_origin!(key)

    defp validate_origin_value!(key, url, opts) do
      trimmed = String.trim_trailing(url, "/")

      case validate_origin(trimmed, Keyword.get(opts, :allow_http, false)) do
        {:ok, origin} -> origin
        :error -> raise_invalid_origin!(key)
      end
    end

    # An origin pin must be an absolute `http(s)://host` base URL. Trim the trailing
    # slash first, then validate with URI.new/1 and require an http/https scheme and
    # a non-empty host, with no userinfo/query/fragment - so blank, relative, or
    # malformed pins ("", "/", "///", "/prefix", "mcp.example.com", "://x",
    # "https:///path", "https://u:p@h", "https://h?x=1", "https://h#f") are rejected
    # and raise rather than concatenating into a relative, authority-less, or
    # credential-leaking `resource` / well-known URL. A port and a path prefix are
    # allowed (the latter for path-prefix proxies).
    defp validate_origin(trimmed, allow_http?) when is_boolean(allow_http?) do
      if AttestoURI.issuer_identifier?(trimmed, allow_http: allow_http?), do: {:ok, trimmed}, else: :error
    end

    defp validate_origin(_trimmed, _allow_http?), do: :error

    defp raise_invalid_origin!(key) do
      raise ArgumentError,
            "#{inspect(key)} must resolve to an absolute HTTPS origin without userinfo, query, or fragment; " <>
              "set allow_http: true only for a deliberate development endpoint"
    end

    # The authorization server is advertised verbatim: an issuer identifier is
    # compared by exact string match (RFC 8414 / OIDC Discovery), so - unlike a
    # resource origin - its trailing slash MUST be preserved or discovery breaks.
    #
    # An explicit `:issuer` is authoritative. A malformed explicit value fails
    # closed rather than falling through to a different config issuer.
    defp configured_issuer!(opts) do
      issuer =
        case Keyword.fetch(opts, :issuer) do
          {:ok, issuer} -> issuer
          :error -> config_issuer(Keyword.get(opts, :config))
        end

      if valid_issuer?(issuer) do
        issuer
      else
        raise ArgumentError,
              "protected-resource metadata requires :authorization_servers, a valid HTTPS :issuer, " <>
                "or :config resolving to an Attesto config with a valid HTTPS issuer"
      end
    end

    defp validate_authorization_source!(opts) do
      case Keyword.fetch(opts, :issuer) do
        {:ok, issuer} when is_binary(issuer) ->
          if valid_issuer?(issuer),
            do: :ok,
            else: raise(ArgumentError, ":issuer must be a valid HTTPS issuer identifier")

        {:ok, _invalid} ->
          raise ArgumentError, ":issuer must be a valid HTTPS issuer identifier"

        :error ->
          validate_config_source!(Keyword.fetch!(opts, :config))
      end
    end

    defp validate_config_source!(%Config{}), do: :ok
    defp validate_config_source!(fun) when is_function(fun, 0), do: :ok
    defp validate_config_source!({module, fun}) when is_atom(module) and is_atom(fun), do: :ok

    defp validate_config_source!({module, fun, args}) when is_atom(module) and is_atom(fun) and is_list(args), do: :ok

    defp validate_config_source!(_invalid) do
      raise ArgumentError, ":config must be an Attesto config, a zero-arity function, or an MFA tuple"
    end

    defp config_issuer(%Config{issuer: issuer}) when is_binary(issuer), do: issuer
    defp config_issuer(callback) when is_function(callback, 0), do: config_issuer(Auth.invoke(callback, []))

    defp config_issuer({module, fun} = callback) when is_atom(module) and is_atom(fun),
      do: config_issuer(Auth.invoke(callback, []))

    defp config_issuer({module, fun, args} = callback) when is_atom(module) and is_atom(fun) and is_list(args),
      do: config_issuer(Auth.invoke(callback, []))

    defp config_issuer(_), do: nil

    defp base_url(%Plug.Conn{} = conn) do
      URI.to_string(%URI{
        scheme: Atom.to_string(conn.scheme),
        host: conn.host,
        port: conn.port
      })
    end

    defp validate_authorization_servers!(servers) when is_list(servers) and servers != [] do
      if Enum.uniq(servers) != servers or not Enum.all?(servers, &valid_issuer?/1) do
        raise ArgumentError,
              ":authorization_servers must be a non-empty unique list of HTTPS issuer identifiers"
      end

      :ok
    end

    defp validate_authorization_servers!(_servers) do
      raise ArgumentError,
            ":authorization_servers must be a non-empty unique list of HTTPS issuer identifiers"
    end

    defp valid_issuer?(issuer), do: AttestoURI.issuer_identifier?(issuer)
    @doc "Validate one metadata route declaration and separate its root ownership option."
    def mount_options(resource_path, opts) do
      path = normalize_resource_path!(resource_path)
      {root, metadata_opts} = Keyword.pop(opts, :root, :auto)
      validate_metadata_options!(metadata_opts)

      if path == "/" and root == false do
        raise ArgumentError,
              "root: false cannot be used when resource_path is / because its RFC 9728 metadata route is the root document"
      end

      {path, root, metadata_opts}
    end

    @doc "Validate a resource URL, permitting HTTP only for loopback under explicit opt-in."
    def resource_url?(url, allow_http?), do: AttestoURI.https_identifier?(url, allow_loopback_http: allow_http?)

    @doc "Translate the router's scopes alias to the RFC 9728 field."
    def metadata_options(opts) do
      case Keyword.pop(opts, :scopes) do
        {nil, remaining} -> remaining
        {scopes, remaining} -> Keyword.put_new(remaining, :scopes_supported, scopes)
      end
    end

    @doc "Cache only metadata whose resource is statically pinned."
    def cache_control(opts), do: if(static_pin?(opts), do: "public, max-age=3600", else: "no-store")
  end
end
