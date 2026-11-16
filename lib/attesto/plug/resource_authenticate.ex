if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.ResourceAuthenticate do
    @moduledoc """
    Authenticate one OAuth protected resource using `Attesto.Plug.Authenticate`.

    Requires an explicit `:resource_audience` or `:trusted_audiences` policy.
    With `resource_audience: :resource`, use `:resource_path` and a pinned
    `:base_url` or `:origin`. Never derive an audience from an unchecked Host.
    A DPoP mount requires a pin or an explicit `:htu` callback at initialization;
    `:allow_dynamic_origin` also supports a non-empty `:allowed_hosts` allowlist.
    HTTP pins require `allow_http: true` and loopback.

    `:base_url` / `:origin` accepts a URL, one-arity callback or MFA tuple.
    `:resource_audience` also accepts a literal identifier, callback or MFA.
    `:resource_metadata_url` overrides the derived RFC 9728 challenge pointer;
    `:www_authenticate` overrides challenge rendering entirely.
    `:principal` receives verified claims and sender context and returns
    `{:ok, principal}` or `{:error, reason}`. The exact error result
    `{:error, {:temporarily_unavailable, reason}}` answers 503
    `temporarily_unavailable`, without a challenge or `Retry-After`. The reason
    is discarded. Every other result answers 401 `invalid_token`. An exception
    the callback raises is not caught, as with the verifier: it reaches the
    host's error handling, which typically answers 500. MFA extras follow call
    arguments.

    Assign keys are configurable with `:claims_key` (default `:attesto_claims`),
    `:scopes_key` (`:attesto_scopes`), `:sender_key` (`:attesto_sender`),
    `:principal_key` (`:attesto_principal`) and `:context_key` (`:attesto_context`).
    The context contains subject, client_id, scope, claims, cnf and principal.
    `:policy_rejection_send_error` optionally supplies a separate error renderer
    for principal refusals; otherwise `:send_error` handles them too.
    `:principal_unavailable_send_error` similarly overrides `:send_error` for
    principal outages. Both hooks receive `(conn, status, body)`.

    Outcome hooks distinguish `:policy_rejected` (401 principal refusal),
    `:principal_unavailable` (503 principal outage), and `:verifier_unavailable`
    (503 verifier outage through `:send_error`). A status/body alone cannot
    distinguish the two outage outcomes.

    All other `Attesto.Plug.Authenticate` options pass through, including
    `:config`, `:verify`, `:replay_check`, `:nonce_check`, `:nonce_issue`,
    `:cert_der`, `:htu`, `:credential_from_conn`, `:bearer_methods`, `:step_up`,
    `:send_error`, `:www_authenticate`, `:no_store` and verification options.
    With no explicit `:bearer_methods`, the base plug's defaults apply.
    Use `Attesto.Plug.ProtectResource` to add per-route scope authorization.
    """

    @behaviour Plug

    import Plug.Conn

    alias Attesto.Plug.Authenticate, as: AttestoAuthenticate
    alias Attesto.Plug.OAuthError
    alias Attesto.ResourceContext, as: Auth
    alias Attesto.ResourceMetadata, as: Metadata

    require Logger

    @claims_key :attesto_claims
    @scopes_key :attesto_scopes
    @sender_key :attesto_sender
    @principal_key :attesto_principal
    @context_key :attesto_context
    @resource_option_keys [
      :allow_dynamic_origin,
      :allowed_hosts,
      :base_url,
      :context_key,
      :origin,
      :principal,
      :principal_key,
      :policy_rejection_send_error,
      :principal_unavailable_send_error,
      :resource_audience,
      :resource_path,
      :scopes_key,
      :sender_key
    ]

    @impl Plug
    def init(opts) when is_list(opts) do
      Attesto.ResourcePolicy.validate_htu_opt!(opts)
      Attesto.ResourcePolicy.validate_dynamic_origin_options!(opts)
      Attesto.ResourcePolicy.validate_dpop_pin!(opts)
      Metadata.validate_origin_options!(opts)
      Attesto.ResourcePolicy.validate_resource_path!(opts)
      Attesto.ResourcePolicy.validate_audience_policy!(opts)
      Attesto.ResourcePolicy.validate_resource_metadata_url!(opts)

      normalized_core_opts =
        opts
        |> core_opts(Keyword.get(opts, :claims_key, @claims_key))
        |> AttestoAuthenticate.normalize_options(require_dpop_pin?: false)

      # Retain resource configuration while preserving every validation and
      # normalization performed by the core plug at pipeline initialization.
      Keyword.merge(normalized_core_opts, Keyword.take(opts, @resource_option_keys))
    end

    @impl Plug
    def call(conn, opts) do
      claims_key = Keyword.get(opts, :claims_key, @claims_key)
      authenticate_request(conn, opts, claims_key)
    end

    defp authenticate_request(conn, opts, claims_key) do
      if dynamic_host_forbidden?(conn, opts) do
        OAuthError.unauthorized(
          conn,
          :bearer,
          "invalid_token",
          error_opts(opts, description: "request host is not allowed")
        )
      else
        core =
          opts
          |> put_resource_audience(conn, opts)
          |> put_pinned_htu(opts)

        conn = AttestoAuthenticate.call(conn, core)
        if conn.halted, do: conn, else: assign_context(conn, opts, claims_key)
      end
    end

    defp dynamic_host_forbidden?(conn, opts) do
      Keyword.get(opts, :allow_dynamic_origin) == true and
        not host_allowed?(conn, Keyword.get(opts, :allowed_hosts, []))
    end

    @doc false
    @spec host_allowed?(Plug.Conn.t(), [String.t()]) :: boolean()
    def host_allowed?(conn, hosts) when is_list(hosts) do
      case normalize_allowed_host(conn.host) do
        "" ->
          false

        host ->
          authority = host <> ":" <> Integer.to_string(conn.port)
          Enum.any?(hosts, fn allowed -> normalize_allowed_host(allowed) in [host, authority] end)
      end
    end

    defp normalize_allowed_host(host) when is_binary(host) do
      host
      |> String.trim()
      |> String.replace(["[", "]"], "")
      |> String.trim_trailing(".")
      |> String.downcase(:ascii)
    end

    defp normalize_allowed_host(_host), do: ""

    # RFC 8707 / RFC 9728: enforce that the access token is audienced to THIS
    # protected resource. When `:resource_audience` is set, the token's `aud` is
    # checked through Attesto's strict `:trusted_audiences` policy against this
    # resource's identifier (the same value advertised as the RFC 9728 metadata
    # `resource`). This rejects both a sibling scalar audience and an array that
    # mixes this resource with any other audience. The identifier is computed per
    # request because it honors the pinned origin or explicit callback; absent,
    # initialization requires an explicit core trust policy instead.
    defp put_resource_audience(core, conn, opts) do
      case Keyword.get(opts, :resource_audience) do
        nil -> core
        false -> core
        policy -> Keyword.put(core, :trusted_audiences, [resolve_resource_audience(policy, conn, opts)])
      end
    end

    # RFC 9449 §4.3: a DPoP proof is bound to the URI of the request it was made
    # for. Attesto core builds that URI from the request scheme, `Host` header,
    # and port unless it is given `:htu`, so a server that answers any `Host`
    # would accept a proof made for another server. A pinned `:base_url` /
    # `:origin` is the origin clients address this resource by, so it also fixes
    # the URI a proof must sign. The callback is built per request rather than in
    # `init/1`, which must stay escape-safe for compile-time pipelines, and it is
    # passed as `:htu` because every Attesto core this package supports accepts
    # that option (core `:origin` cannot carry a callback, an `http` development
    # origin, or a path prefix). A host-supplied `:htu` is left in place.
    defp put_pinned_htu(core, opts) do
      if not Keyword.has_key?(opts, :htu) and
           (origin_pinned?(opts) or Keyword.get(opts, :allow_dynamic_origin) == true) do
        Keyword.put(core, :htu, &dpop_target_uri(&1, opts))
      else
        core
      end
    end

    defp origin_pinned?(opts), do: Enum.any?([:base_url, :origin], &Keyword.has_key?(opts, &1))

    @doc """
    Returns the DPoP target URI (`htu`) a proof must sign for `conn` when the
    plug is configured with `opts` and no `:htu`: the origin resolved by
    `Attesto.ResourceMetadata.resolve_origin/2` followed by `conn.request_path`.

    With a pinned `:base_url` or `:origin`, the request's scheme, `Host` header,
    and port do not affect the result. A pinned value carrying a path prefix is
    joined with `conn.request_path`, which matches a proxy that strips that
    prefix before the request reaches the application. Without a pin, the
    resolved origin is the request's own.

        iex> conn = Plug.Test.conn(:post, "http://10.0.0.5:4000/mcp")
        iex> Attesto.Plug.ResourceAuthenticate.dpop_target_uri(conn, base_url: "https://mcp.example.com")
        "https://mcp.example.com/mcp"
    """
    @spec dpop_target_uri(Plug.Conn.t(), keyword()) :: String.t()
    def dpop_target_uri(%Plug.Conn{} = conn, opts) when is_list(opts) do
      Metadata.resolve_origin(conn, opts) <> conn.request_path
    end

    # `:resource` derives the identifier from the configured `:resource_path` and
    # resolved origin. Other supported values are literal identifiers or
    # `(conn -> identifier)` callbacks in function / MFA form. A callback result
    # is deliberately not treated as an enable/disable signal: malformed values
    # become a malformed one-item core trust list and fail token verification.
    defp resolve_resource_audience(:resource, conn, opts) do
      identifier = Metadata.resource_identifier(conn, Keyword.fetch!(opts, :resource_path), opts)
      if Metadata.resource_url?(identifier, Keyword.get(opts, :allow_http, false)), do: identifier
    end

    defp resolve_resource_audience(value, conn, _opts), do: invoke_resource_audience(value, conn)

    defp invoke_resource_audience(value, _conn) when is_binary(value), do: value
    defp invoke_resource_audience(callback, conn), do: Auth.invoke(callback, [conn])

    defp assign_context(conn, opts, claims_key) do
      claims = conn.assigns[claims_key]
      sender = sender_context(claims)
      scopes = Auth.scopes(claims)

      # Resolve the optional principal before assigning the verified context.
      case resolve_principal(opts, claims, sender) do
        {:ok, principal} ->
          conn
          |> assign(Keyword.get(opts, :scopes_key, @scopes_key), scopes)
          |> assign(Keyword.get(opts, :sender_key, @sender_key), sender)
          |> assign(Keyword.get(opts, :principal_key, @principal_key), principal)
          |> assign(Keyword.get(opts, :context_key, @context_key), context(claims, scopes, principal))

        :principal_unavailable ->
          OAuthError.temporarily_unavailable(
            conn,
            error_opts(opts,
              send_error: Keyword.get(opts, :principal_unavailable_send_error, Keyword.get(opts, :send_error))
            )
          )

        :error ->
          # The refusal is rendered as a generic invalid_token; the recording
          # hook is told the exact outcome because the envelope cannot show it.
          OAuthError.unauthorized(
            conn,
            Auth.scheme(claims),
            "invalid_token",
            error_opts(opts, send_error: policy_rejection_hook(opts))
          )
      end
    end

    defp resolve_principal(opts, claims, sender) do
      case Keyword.get(opts, :principal) do
        nil ->
          {:ok, nil}

        callback ->
          case Auth.invoke(callback, [claims, sender]) do
            {:ok, principal} -> {:ok, principal}
            {:error, {:temporarily_unavailable, _reason}} -> :principal_unavailable
            _rejected -> :error
          end
      end
    end

    # The context uses the same fields across resource adapters.
    defp context(claims, scopes, principal) do
      %{
        subject: claims["sub"],
        client_id: claims["client_id"],
        scope: scopes,
        claims: claims,
        cnf: Map.get(claims, "cnf"),
        principal: principal
      }
    end

    @doc false
    @spec oauth_error_opts(keyword()) :: keyword()
    def oauth_error_opts(opts),
      do: Keyword.take(opts, [:send_error, :www_authenticate, :no_store, :resource_metadata, :allow_http])

    @doc false
    @spec oauth_error_metadata_opts(keyword()) :: keyword()
    def oauth_error_metadata_opts(opts) do
      if Keyword.has_key?(opts, :www_authenticate) do
        []
      else
        []
        |> maybe_put_opt(:resource_metadata, metadata_url_resolver(opts))
        |> maybe_copy_opt(opts, :allow_http)
      end
    end

    @doc false

    @spec metadata_www_authenticate(keyword()) :: (Plug.Conn.t(), String.t() -> Plug.Conn.t()) | nil
    def metadata_www_authenticate(opts) do
      cond do
        Keyword.has_key?(opts, :www_authenticate) ->
          nil

        metadata_url = metadata_url_resolver(opts) ->
          fn conn, challenge ->
            rendered = render_metadata_challenge(challenge, resolve_metadata_url(metadata_url, conn), opts)
            put_resp_header(conn, "www-authenticate", rendered)
          end

        true ->
          nil
      end
    end

    defp render_metadata_challenge(challenge, url, opts) do
      if Metadata.resource_url?(url, Keyword.get(opts, :allow_http, false)) do
        append_resource_metadata = Function.capture(Metadata, :append_resource_metadata, 2)
        append_resource_metadata.(challenge, url)
      else
        challenge
      end
    end

    @doc false
    # Compatibility arity: this intentionally preserves the 2.0 callback/fallback
    # behavior and does not validate the returned URL. New internal integrations
    # use resolve_resource_metadata_url/4, which validates the selected URL.
    @spec resolve_resource_metadata_url(Plug.Conn.t(), term(), term()) :: term()
    def resolve_resource_metadata_url(conn, callback, fallback) do
      case resolve_metadata_url(callback, conn) do
        url when is_binary(url) and url != "" -> url
        _invalid -> resolve_metadata_url(fallback, conn)
      end
    end

    @doc false
    # Core invokes this MFA when a host callback has a derived-path fallback.
    # Invalid callback results are omitted, with a VM-wide warning emitted
    # once, instead of disappearing silently inside core's challenge renderer.
    @spec resolve_resource_metadata_url(Plug.Conn.t(), term(), term(), boolean()) :: term()
    def resolve_resource_metadata_url(conn, callback, fallback, allow_http?) do
      callback
      |> resolve_metadata_url(conn)
      |> valid_resource_metadata_url(allow_http?)
      |> case do
        {:ok, url} ->
          url

        :error ->
          warn_invalid_resource_metadata_once()
          resolve_validated_resource_metadata_url(conn, fallback, allow_http?)
      end
    end

    @doc false
    @spec resolve_validated_resource_metadata_url(Plug.Conn.t(), term(), boolean()) :: term()
    def resolve_validated_resource_metadata_url(conn, resolver, allow_http?) do
      resolver
      |> resolve_metadata_url(conn)
      |> valid_resource_metadata_url(allow_http?)
      |> case do
        {:ok, url} ->
          url

        :error ->
          warn_invalid_resource_metadata_once()
          nil
      end
    end

    defp policy_rejection_hook(opts) do
      Keyword.get(opts, :policy_rejection_send_error, Keyword.get(opts, :send_error))
    end

    # `:origin` is dropped along with the other resource-specific keys even though core
    # has an option of the same name: the resource adapter also accepts callbacks, an
    # `http` origin under `:allow_http`, and a path prefix, none of which core's
    # `:origin` takes. The pinned origin reaches core as an `:htu` callback in
    # `call/2` instead.
    defp core_opts(opts, claims_key) do
      opts
      |> Keyword.drop([
        :allow_dynamic_origin,
        :allowed_hosts,
        :base_url,
        :context_key,
        :origin,
        :issuer,
        :principal,
        :principal_key,
        :resource_metadata_url,
        :resource_path,
        :resource_audience,
        :scopes_key,
        :sender_key
      ])
      |> Keyword.put(:claims_key, claims_key)
      |> put_oauth_error_metadata(opts)
    end

    defp put_oauth_error_metadata(core_opts, opts) do
      if Keyword.has_key?(opts, :www_authenticate) do
        Keyword.delete(core_opts, :resource_metadata)
      else
        core_opts
        |> maybe_put_opt(:resource_metadata, metadata_url_resolver(opts))
        |> maybe_copy_opt(opts, :allow_http)
      end
    end

    defp metadata_url_resolver(opts) do
      opts
      |> Keyword.get(:resource_metadata_url)
      |> metadata_url_resolver(opts)
    end

    defp metadata_url_resolver(url, _opts) when is_binary(url), do: url

    defp metadata_url_resolver(callback, opts)
         when is_function(callback, 1) or (is_tuple(callback) and tuple_size(callback) in [2, 3]),
         do: metadata_callback(callback, opts)

    defp metadata_url_resolver(nil, opts), do: validated_metadata_fallback(opts)
    defp metadata_url_resolver(_invalid, _opts), do: nil

    # The challenge URL must agree with the served metadata `resource`, so resolve
    # its origin the same way `Attesto.ResourceMetadata` does: a pinned `:base_url` /
    # `:origin` wins over the request connection. (The issuer is not used here -
    # it is the authorization server, not the resource origin.)
    defp metadata_url_from_resource_path(path, opts) when is_binary(path) do
      origin_opts = Keyword.take(opts, [:base_url, :origin, :allow_http])
      {Metadata, :protected_resource_url, [path, origin_opts]}
    end

    defp metadata_url_from_resource_path(_path, _opts), do: nil

    defp metadata_callback(callback, opts) do
      fallback = metadata_url_from_resource_path(Keyword.get(opts, :resource_path), opts)
      allow_http? = Keyword.get(opts, :allow_http, false)

      if fallback,
        do: {__MODULE__, :resolve_resource_metadata_url, [callback, fallback, allow_http?]},
        else: {__MODULE__, :resolve_validated_resource_metadata_url, [callback, allow_http?]}
    end

    defp validated_metadata_fallback(opts) do
      case metadata_url_from_resource_path(Keyword.get(opts, :resource_path), opts) do
        nil ->
          nil

        fallback ->
          {__MODULE__, :resolve_validated_resource_metadata_url, [fallback, Keyword.get(opts, :allow_http, false)]}
      end
    end

    defp valid_resource_metadata_url(url, allow_http?) do
      if Metadata.resource_url?(url, allow_http?), do: {:ok, url}, else: :error
    end

    defp warn_invalid_resource_metadata_once do
      key = {__MODULE__, :invalid_resource_metadata_warning_emitted}

      if !:persistent_term.get(key, false) do
        :persistent_term.put(key, true)

        Logger.warning(
          "Attesto omitted an invalid resource_metadata callback result; " <>
            "return an absolute HTTPS URL or set allow_http: true for development"
        )
      end
    end

    defp resolve_metadata_url(url, _conn) when is_binary(url), do: url
    defp resolve_metadata_url(callback, conn), do: Auth.invoke(callback, [conn])

    defp sender_context(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt) do
      %{binding: :dpop, jkt: jkt}
    end

    defp sender_context(%{"cnf" => %{"x5t#S256" => thumbprint}}) when is_binary(thumbprint) do
      %{binding: :mtls, x5t_s256: thumbprint}
    end

    defp sender_context(_claims), do: %{binding: :bearer}

    defp error_opts(opts, extra) do
      opts
      |> oauth_error_opts()
      |> Keyword.merge(extra)
    end

    defp maybe_put_opt(opts, _key, nil), do: opts
    defp maybe_put_opt(opts, key, value), do: Keyword.put(opts, key, value)

    defp maybe_copy_opt(target, source, key) do
      case Keyword.fetch(source, key) do
        {:ok, value} -> Keyword.put(target, key, value)
        :error -> target
      end
    end
  end
end
