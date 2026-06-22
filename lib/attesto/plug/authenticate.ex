if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.Plug.Authenticate do
    @moduledoc """
    Authenticate a protected-resource request: verify the access token and,
    for a DPoP-bound or mTLS-bound token, the sender-constraint proof.

    A thin wrapper over the pure verifiers (`Attesto.Token`, `Attesto.DPoP`,
    `Attesto.MTLS`). It does the HTTP-specific work - parsing the
    `Authorization` and `DPoP` headers, building the `htu`, computing the
    client-certificate thumbprint via a host callback, wiring the replay
    and nonce checks - then delegates every decision to the engine and
    assigns the verified claims onto the conn.

    ## Options

      * `:config` (required) - an `Attesto.Config` or a zero-arity function
        returning one.
      * `:replay_check` - the DPoP `:replay_check` callback
        (`(jti, ttl) -> :ok | {:error, :replay}`), e.g.
        `&Attesto.DPoP.ReplayCache.check_and_record/2`. **Required for DPoP**:
        without it, RFC 9449 §11.1 replay rejection is off and a captured
        proof can be replayed within the `iat` window. This plug therefore
        fails closed - a DPoP request is rejected (401 `invalid_dpop_proof`,
        `replay_check_unconfigured`) unless `:replay_check` is wired, so an
        unprotected DPoP endpoint cannot silently ship. Bearer/mTLS requests
        are unaffected. A host that knowingly accepts unprotected DPoP sets
        `dpop_replay_unprotected_acknowledged?: true` to opt out.
      * `:dpop_replay_unprotected_acknowledged?` - set to `true` to allow
        DPoP requests through WITHOUT `:replay_check`, accepting that
        captured proofs are replayable. Off by default (fail closed).
      * `:nonce_check` - the DPoP `:nonce_check` callback
        (`(nonce | nil) -> :ok | {:error, :use_dpop_nonce}`).
      * `:nonce_issue` - a zero-arity function returning a fresh DPoP nonce
        for the `use_dpop_nonce` challenge (required if `:nonce_check` is
        set), e.g. `&Attesto.DPoP.NonceStore.ETS.issue/0`.
      * `:cert_der` - `(conn -> der_binary | nil)`; the DER of the client
        certificate the TLS layer authenticated. TLS termination varies, so
        the host supplies it. When it returns a certificate, its RFC 8705
        thumbprint is handed to `Attesto.Token.verify/3`.
      * `:htu` - `(conn -> https_uri_string)` overriding how the request URI
        (without query/fragment) is built; default uses `conn` directly,
        which requires the scheme/host to reflect the external request
        (configure your proxy-forwarding rewrite).
      * `:credential_from_conn` - optional fallback
        `(conn -> {:ok, :bearer | :dpop, token} | :missing)`. Use this for
        host-owned credential channels such as first-party cookies. The
        standard `Authorization` header remains authoritative when present;
        this callback is consulted only when no usable header credential is
        present.
      * `:bearer_methods` - standard RFC 6750 Bearer-token presentation
        methods this resource server accepts. Allowed values are `:header` /
        `"header"` (RFC 6750 §2.1 `Authorization: Bearer`) and `:body` /
        `"body"` (RFC 6750 §2.2 form-body `access_token`). Defaults to
        `[:header]`. Add `:body` only when the protected-resource metadata
        advertises body support and the deployment accepts the logging,
        caching, retry, and replay risks of credentials in request bodies.
        The URI-query method is intentionally unsupported. This setting does
        not disable `Authorization: DPoP`, mTLS binding, or a host-owned
        `:credential_from_conn` fallback.
      * `:claims_key` - the `conn.assigns` key the verified claims are put
        under (default `:attesto_claims`).
      * `:send_error`, `:www_authenticate`, `:no_store` - optional transport
        hooks forwarded to `Attesto.Plug.OAuthError` so a host can keep its
        own JSON error envelope while Attesto owns the RFC status/challenge
        semantics.
      * `:resource_metadata` - the URL of this resource's protected-resource
        metadata (RFC 9728), advertised as a `resource_metadata` auth-param on
        every 401 `WWW-Authenticate` challenge (RFC 9728 §5.1) so a client that
        is refused can discover the authorization server.

        plug Attesto.Plug.Authenticate,
          config: &MyApp.Attesto.config/0,
          replay_check: &MyApp.DPoPReplay.check_and_record/2,
          cert_der: &MyApp.TLS.client_cert_der/1
    """

    @behaviour Plug

    import Plug.Conn

    alias Attesto.DPoP
    alias Attesto.MTLS
    alias Attesto.Plug.OAuthError
    alias Attesto.StepUp.Requirement
    alias Attesto.Token

    @default_claims_key :attesto_claims
    @default_bearer_methods [:header]
    @supported_bearer_methods [:header, :body]

    @impl Plug
    def init(opts) do
      # RFC 9449 §8: a `use_dpop_nonce` challenge is only actionable if it
      # carries a `DPoP-Nonce` header for the client to echo. If the host
      # wires a `:nonce_check` (which can demand a nonce) it MUST also wire
      # a `:nonce_issue` to mint one, or the challenge is a dead end. Fail
      # at boot, not at the first nonce-less request.
      if Keyword.has_key?(opts, :nonce_check) and not Keyword.has_key?(opts, :nonce_issue) do
        raise ArgumentError,
              "Attesto.Plug.Authenticate: :nonce_check requires :nonce_issue so a " <>
                "use_dpop_nonce challenge can carry a DPoP-Nonce header."
      end

      opts
      |> Keyword.put(:bearer_methods, bearer_methods(opts))
      |> normalize_step_up()
    end

    # RFC 9470: a route may declare a step-up requirement (`step_up:
    # [acr_values: [...], max_age: ...]` or a `%Attesto.StepUp.Requirement{}`).
    # Parse + validate it at boot so a malformed requirement fails closed here
    # rather than silently never (or always) challenging at request time.
    defp normalize_step_up(opts) do
      case Keyword.fetch(opts, :step_up) do
        :error -> opts
        {:ok, spec} -> Keyword.put(opts, :step_up, Requirement.parse(spec))
      end
    end

    @impl Plug
    def call(conn, opts) do
      config = resolve_config(opts)

      with {:ok, scheme, token} <- authorization(conn, opts),
           {:ok, dpop_jkt} <- verify_dpop(conn, scheme, token, opts),
           {:ok, mtls_thumb} <- cert_thumbprint(conn, opts),
           {:ok, claims} <- verify_token(config, token, dpop_jkt, mtls_thumb) do
        conn = assign(conn, Keyword.get(opts, :claims_key, @default_claims_key), claims)

        # RFC 9470 §3: after the token is verified, enforce any route step-up
        # requirement against its authentication-context claims; an unsatisfied
        # requirement halts with the `insufficient_user_authentication` challenge.
        case step_up_check(claims, opts) do
          :ok ->
            conn

          {:challenge, challenge} ->
            OAuthError.insufficient_user_authentication(conn, step_up_scheme(claims), challenge, error_opts(opts, []))
        end
      else
        :missing ->
          OAuthError.unauthorized(
            conn,
            :bearer,
            "invalid_token",
            error_opts(opts, description: "missing or malformed Authorization header")
          )

        {:dpop_error, :use_dpop_nonce} ->
          OAuthError.unauthorized(conn, :dpop, "use_dpop_nonce", error_opts(opts, dpop_nonce: issue_nonce(opts)))

        {:dpop_error, reason} ->
          OAuthError.unauthorized(
            conn,
            :dpop,
            "invalid_dpop_proof",
            error_opts(opts, description: to_string(reason))
          )

        {:token_error, reason} ->
          OAuthError.unauthorized(
            conn,
            token_error_scheme(conn, reason),
            "invalid_token",
            error_opts(opts, description: to_string(reason))
          )
      end
    end

    # ----- authorization header -----

    defp authorization(conn, opts) do
      case get_req_header(conn, "authorization") do
        [value] -> parse_authorization(value, opts)
        [] -> fallback_authorization(conn, opts)
        _ -> :missing
      end
    end

    defp parse_authorization(value, opts) do
      case String.split(value, " ", parts: 2) do
        [scheme, token] ->
          case String.downcase(scheme) do
            "bearer" -> bearer_header_authorization(token, opts)
            "dpop" -> authorization_token(:dpop, token)
            _ -> :missing
          end

        _ ->
          :missing
      end
    end

    defp bearer_header_authorization(token, opts) do
      if bearer_method?(opts, :header), do: authorization_token(:bearer, token), else: :missing
    end

    defp authorization_token(scheme, token) do
      case String.trim(token) do
        "" -> :missing
        token -> {:ok, scheme, token}
      end
    end

    # RFC 6750 §2.2 permits bearer tokens in an application/x-www-form-urlencoded
    # request body. Keep this opt-in and fallback-only: an Authorization header
    # remains the primary credential channel, and GET query tokens are
    # intentionally not accepted here.
    defp form_body_authorization(%Plug.Conn{method: "POST", body_params: %{"access_token" => token}} = conn)
         when is_binary(token) do
      if form_urlencoded?(conn), do: authorization_token(:bearer, token), else: :missing
    end

    defp form_body_authorization(_conn), do: :missing

    defp fallback_authorization(conn, opts) do
      case custom_authorization(conn, opts) do
        :missing -> maybe_form_body_authorization(conn, opts)
        result -> result
      end
    end

    defp maybe_form_body_authorization(conn, opts) do
      if bearer_method?(opts, :body) do
        form_body_authorization(conn)
      else
        :missing
      end
    end

    defp form_urlencoded?(conn) do
      conn
      |> get_req_header("content-type")
      |> Enum.any?(fn value ->
        value
        |> String.downcase()
        |> String.starts_with?("application/x-www-form-urlencoded")
      end)
    end

    defp custom_authorization(conn, opts) do
      case Keyword.get(opts, :credential_from_conn) do
        fun when is_function(fun, 1) ->
          normalize_custom_authorization(fun.(conn))

        _ ->
          :missing
      end
    end

    defp normalize_custom_authorization({:ok, scheme, token}) when scheme in [:bearer, :dpop] and is_binary(token) do
      case String.trim(token) do
        "" -> :missing
        token -> {:ok, scheme, token}
      end
    end

    defp normalize_custom_authorization(:missing), do: :missing
    defp normalize_custom_authorization(_other), do: :missing

    defp bearer_method?(opts, method), do: method in bearer_methods(opts)

    defp bearer_methods(opts) do
      opts
      |> Keyword.get(:bearer_methods, @default_bearer_methods)
      |> normalize_bearer_methods()
    end

    defp normalize_bearer_methods(methods) when is_list(methods) do
      normalized = Enum.map(methods, &normalize_bearer_method/1)

      if normalized != [] and normalized == Enum.uniq(normalized) and
           Enum.all?(normalized, &(&1 in @supported_bearer_methods)) do
        normalized
      else
        raise ArgumentError,
              "Attesto.Plug.Authenticate: :bearer_methods must be a non-empty list of distinct " <>
                "RFC 6750 methods accepted by this resource server " <>
                "(#{inspect(@supported_bearer_methods)}); got #{inspect(methods)}."
      end
    end

    defp normalize_bearer_methods(methods) do
      raise ArgumentError,
            "Attesto.Plug.Authenticate: :bearer_methods must be a non-empty list of distinct " <>
              "RFC 6750 methods accepted by this resource server " <>
              "(#{inspect(@supported_bearer_methods)}); got #{inspect(methods)}."
    end

    defp normalize_bearer_method(:header), do: :header
    defp normalize_bearer_method("header"), do: :header
    defp normalize_bearer_method(:body), do: :body
    defp normalize_bearer_method("body"), do: :body
    defp normalize_bearer_method(other), do: other

    # ----- DPoP proof -----

    # Only a DPoP-scheme request carries a proof. A Bearer request is not
    # DPoP-bound here; if the token itself demands DPoP, Token.verify
    # returns :dpop_proof_required and we surface it as invalid_token.
    defp verify_dpop(conn, :dpop, token, opts) do
      case get_req_header(conn, "dpop") do
        [proof] ->
          verify_dpop_proof(conn, proof, token, opts)

        _ ->
          {:dpop_error, :missing_proof}
      end
    end

    # RFC 9449 §7.1: a DPoP proof is bound to the `DPoP` authentication
    # scheme. A request that carries a `DPoP` header while presenting its
    # token under `Authorization: Bearer` is mixing schemes - the proof is
    # not validated against anything and an mTLS- or bearer-bound token
    # could be shipped alongside an arbitrary proof. Reject it and steer
    # the client to the DPoP scheme rather than ignoring the header.
    defp verify_dpop(conn, :bearer, _token, _opts) do
      case get_req_header(conn, "dpop") do
        [_ | _] -> {:dpop_error, :dpop_scheme_required}
        _ -> {:ok, nil}
      end
    end

    # RFC 9449 §11.1: without a replay check, a captured proof is replayable
    # within the iat window. `Attesto.DPoP.verify_proof/2` treats an absent
    # `:replay_check` as "no replay protection" and returns :ok, so an
    # unwired plug would silently authenticate replays. Fail closed: refuse
    # the DPoP request unless the host wired `:replay_check` or explicitly
    # acknowledged running unprotected. This is scoped to DPoP requests, so
    # a Bearer/mTLS-only deployment is never forced to provide a replay
    # store it has no use for.
    defp verify_dpop_proof(conn, proof, token, opts) do
      if replay_protected?(opts) do
        verify_opts =
          [http_method: conn.method, http_uri: htu(conn, opts), access_token: token]
          |> put_opt(:replay_check, Keyword.get(opts, :replay_check))
          |> put_opt(:nonce_check, Keyword.get(opts, :nonce_check))

        case DPoP.verify_proof(proof, verify_opts) do
          {:ok, %{jkt: jkt}} -> {:ok, jkt}
          {:error, reason} -> {:dpop_error, reason}
        end
      else
        {:dpop_error, :replay_check_unconfigured}
      end
    end

    defp replay_protected?(opts) do
      is_function(Keyword.get(opts, :replay_check), 2) or
        Keyword.get(opts, :dpop_replay_unprotected_acknowledged?, false) == true
    end

    # ----- access token -----

    defp verify_token(config, token, dpop_jkt, mtls_thumb) do
      case Token.verify(config, token, dpop_jkt: dpop_jkt, mtls_cert_thumbprint: mtls_thumb) do
        {:ok, claims} -> {:ok, claims}
        {:error, reason} -> {:token_error, reason}
      end
    end

    # ----- mTLS thumbprint -----

    defp cert_thumbprint(conn, opts) do
      case Keyword.get(opts, :cert_der) do
        nil -> {:ok, nil}
        fun when is_function(fun, 1) -> thumbprint_of(fun.(conn))
      end
    end

    defp thumbprint_of(der) when is_binary(der) and byte_size(der) > 0 do
      case MTLS.compute_thumbprint(der) do
        {:ok, thumb} -> {:ok, thumb}
        {:error, _} -> {:token_error, :invalid_certificate}
      end
    end

    defp thumbprint_of(_), do: {:ok, nil}

    # ----- helpers -----

    defp resolve_config(opts) do
      case Keyword.fetch!(opts, :config) do
        fun when is_function(fun, 0) -> fun.()
        config -> config
      end
    end

    # Build the request URL string directly rather than constructing a
    # partial `%URI{}` and round-tripping through `URI.to_string/1`:
    # building the struct field-by-field trips a dialyzer
    # `call_without_opaque` warning on the `URI.to_string/1` call. The
    # output matches `URI.to_string/1` exactly, including its elision of
    # the scheme's default port (443 for https, 80 for http). Query and
    # fragment are intentionally omitted - the engine compares against the
    # normalized htu.
    defp htu(conn, opts) do
      case Keyword.get(opts, :htu) do
        fun when is_function(fun, 1) ->
          fun.(conn)

        _ ->
          scheme = Atom.to_string(conn.scheme)
          scheme <> "://" <> conn.host <> port_suffix(scheme, conn.port) <> conn.request_path
      end
    end

    defp port_suffix("https", 443), do: ""
    defp port_suffix("http", 80), do: ""
    defp port_suffix(_scheme, port), do: ":" <> Integer.to_string(port)

    defp issue_nonce(opts) do
      case Keyword.get(opts, :nonce_issue) do
        fun when is_function(fun, 0) -> fun.()
        _ -> nil
      end
    end

    # A `:dpop_proof_required` token error means the access token is
    # sender-constrained to a DPoP key (`cnf.jkt`) but was not presented
    # with a valid proof - e.g. a DPoP-bound token sent under `Bearer`
    # with no DPoP header. RFC 9449 §7.1 says the resource server answers
    # such a binding failure with a `DPoP` challenge so the client knows
    # to re-present the token under the DPoP scheme. Steer there
    # regardless of whether this particular request carried a DPoP header.
    defp token_error_scheme(_conn, :dpop_proof_required), do: :dpop
    defp token_error_scheme(conn, _reason), do: scheme_for(conn)

    defp scheme_for(conn) do
      case get_req_header(conn, "dpop") do
        [_ | _] -> :dpop
        _ -> :bearer
      end
    end

    defp put_opt(opts, _key, nil), do: opts
    defp put_opt(opts, key, value), do: Keyword.put(opts, key, value)

    defp error_opts(opts, extra) do
      opts
      |> Keyword.take([:send_error, :www_authenticate, :no_store, :resource_metadata])
      |> Keyword.merge(extra)
    end

    # RFC 9470: evaluate the (init-parsed) route step-up requirement against the
    # verified token's authentication-context claims. No requirement => :ok.
    # The spec is normalized via `Requirement.parse/1` here as well as at
    # `init/1`, so a caller that wires this plug WITHOUT going through `init/1`
    # (e.g. the MCP `Authenticate` wrapper, which rebuilds core opts per request)
    # still gets a parsed, validated requirement rather than a raw keyword list.
    # `parse/1` is idempotent on an already-parsed `%Requirement{}`.
    defp step_up_check(claims, opts) do
      case Keyword.get(opts, :step_up) do
        nil ->
          :ok

        spec ->
          case Attesto.StepUp.evaluate(Requirement.parse(spec), claims, step_up_now(opts)) do
            :ok -> :ok
            {:error, :insufficient_user_authentication, challenge} -> {:challenge, challenge}
          end
      end
    end

    # The challenge scheme follows the token's own binding (a DPoP-bound token is
    # presented and re-challenged under DPoP), mirroring the scope-rejection path.
    defp step_up_scheme(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
    defp step_up_scheme(_claims), do: :bearer

    defp step_up_now(opts) do
      case Keyword.get(opts, :now) do
        %DateTime{} = dt -> DateTime.to_unix(dt)
        n when is_integer(n) -> n
        _ -> System.system_time(:second)
      end
    end
  end
end
