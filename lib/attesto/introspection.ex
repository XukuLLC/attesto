defmodule Attesto.Introspection do
  @moduledoc """
  OAuth 2.0 Token Introspection (RFC 7662), conn-free core.

  Given a presented token, decide whether it is currently active and, if so,
  describe it with the RFC 7662 response members. This is the deliberate
  introspection entry point; the transport layer authenticates the caller and
  decides (by content negotiation) whether to return the plain JSON response or
  a signed JWT (`Attesto.SignedIntrospection`, RFC 9701 / FAPI 2.0 Message
  Signing §5.5). Nothing here touches a `conn`.

  ## What "active" means (RFC 7662 §2.2)

    * **Access tokens** are stateless JWTs: a token is active iff it passes the
      full access-token verification (`Attesto.Token.verify/3` - signature,
      issuer, audience, temporal, required claims, principal, and `typ ==
      "access"`), the same checks a resource server applies. The ONE check
      skipped is the sender-constraint **binding** (the proof-key match): the
      `cnf` is part of who may *use* the token, verified when it is presented,
      and the introspecting caller holds no proof key - so introspection passes
      `require_confirmation_binding: false`. The `cnf` *shape* is still
      validated, and the binding is echoed in the response so a resource server
      can check it (RFC 7662 / RFC 8705 §3.2 / RFC 9449).

    * **Refresh tokens** are opaque, stored secrets: a refresh token present in
      the store, unconsumed, and unexpired is reported active, a consumed
      (rotated) or expired one inactive. The stored record's own data contract
      (`Attesto.RefreshToken` build context) carries the subject, granted scope,
      presenting client, and optional DPoP binding, so those RFC 7662 members
      are surfaced when present (`sub`/`scope`/`client_id`/`cnf`) - for a
      resource server, and so an `:authorize` policy can decide per token. A
      store that does not populate them yields the minimal `active`+`exp`
      response.

    * Anything else - a malformed token, a forged signature, an expired token,
      or one absent from the store - is reported inactive (`%{"active" => false}`),
      never an error: RFC 7662 §2.2 forbids a token-existence oracle.

  `token_type_hint` (RFC 7662 §2.1) only reorders which check is tried first; an
  unmatched hint still falls through to the other.
  """

  alias Attesto.{Config, NumericDate, Secret, Token}

  @inactive %{"active" => false}

  # RFC 7662 §2.2 token_type values for the response.
  @bearer "Bearer"
  @dpop "DPoP"

  @type response :: %{required(String.t()) => term()}

  @type opts :: [
          refresh_store: module() | nil,
          token_type_hint: String.t() | nil,
          trusted_audiences: [String.t()] | (map() -> [String.t()]) | nil,
          authorize: (response() -> boolean()) | nil,
          now: integer() | DateTime.t()
        ]

  @doc """
  Introspect `token`, returning the RFC 7662 response map (always `active`,
  plus the token's members when active). Never returns an error.

  Options:

    * `:refresh_store` - an `Attesto.RefreshStore` module to consult for opaque
      refresh tokens; when absent, only access tokens are introspected.
    * `:token_type_hint` - `"access_token"` or `"refresh_token"` (RFC 7662
      §2.1); reorders the attempts, never restricts them.
    * `:trusted_audiences` - a non-empty allowlist of access-token audiences
      this authorization server recognizes for introspection, or a one-arity
      resolver receiving otherwise-verified claims whose `aud` has not yet
      been authorized. Use the resolver only to select RFC 8707 resource policy
      tied to the signed token's original OAuth client; never derive trust from
      `aud` itself. An explicit policy replaces the configured-audience rule,
      so include the configured audience when it should remain accepted. When
      this option is absent, that configured audience remains the only accepted
      value. A malformed value or failing resolver makes the token inactive.
    * `:authorize` - a 1-arity predicate `(response -> boolean)` consulted with
      the active response *before* it is returned (RFC 7662 §4 / RFC 9701 §5:
      the AS MAY restrict which tokens a caller may introspect). The transport
      layer captures the authenticated caller identity in this closure; if it
      does not return `true` - or it raises - the response is downgraded to
      `%{"active" => false}` so a caller not authorized for the token learns
      nothing about it (FAPI: a regular client querying introspection is a
      leakage risk). When absent, every authenticated caller may introspect any
      token (the single-trust-domain default). **Any deployment where more than
      one client can authenticate to introspection MUST set this** — without it,
      client A can introspect a token issued to client B and learn its `sub`,
      `scope`, `aud`, and `exp`. Scope the predicate to the caller (e.g. return
      `true` only when the token's `client_id`/`aud` matches the authenticated
      caller, or per your resource-server trust policy). The predicate is
      fail-closed: a non-`true` return or a raise yields `%{"active" => false}`.
    * `:now` - the reference time (Unix seconds or `DateTime`), for tests.
  """
  @spec introspect(Config.t(), String.t(), opts()) :: response()
  def introspect(%Config{} = config, token, opts \\ []) when is_binary(token) and is_list(opts) do
    opts
    |> ordered_attempts()
    |> Enum.find_value(@inactive, fn attempt -> attempt.(config, token, opts) end)
    |> authorize_caller(opts)
  end

  # RFC 7662 §4 / RFC 9701 §5: an active response is returned to the caller only
  # if the host's caller-authorization predicate accepts it. Fail closed - a
  # predicate that returns anything but `true`, or raises, makes the token
  # inactive to this caller. An inactive result (no token, or not active) is
  # never passed to the predicate: there is nothing to leak and nothing to
  # authorize.
  defp authorize_caller(%{"active" => true} = response, opts) do
    case Keyword.get(opts, :authorize) do
      fun when is_function(fun, 1) -> if safe_authorize(fun, response), do: response, else: @inactive
      _ -> response
    end
  end

  defp authorize_caller(response, _opts), do: response

  defp safe_authorize(fun, response) do
    fun.(response) == true
  rescue
    _ -> false
  end

  # RFC 7662 §2.1: the hint is an optimisation, not a constraint - try the hinted
  # type first, then fall through to the other.
  defp ordered_attempts(opts) do
    attempts = [&access_token_response/3, &refresh_token_response/3]

    case Keyword.get(opts, :token_type_hint) do
      "refresh_token" -> Enum.reverse(attempts)
      _ -> attempts
    end
  end

  # An access token is active iff it passes the full access-token verification
  # (signature, issuer, audience, temporal, required claims, principal, and
  # typ == "access") - the SAME checks the resource-server path applies, so a
  # wrong-audience, non-access, or otherwise invalid token is inactive. Only the
  # sender-binding proof match is skipped (the caller is not the token's
  # presenter and holds no proof key); the `cnf` shape is still validated and
  # the binding is echoed in the response for the resource server to check.
  defp access_token_response(%Config{} = config, token, opts) do
    case Token.verify(config, token, verify_opts(opts)) do
      {:ok, claims} -> rfc7662_response(claims)
      {:error, _reason} -> nil
    end
  end

  defp verify_opts(opts) do
    base = [expected_typ: "access", require_confirmation_binding: false]

    base
    |> put_if_present(:now, Keyword.get(opts, :now))
    |> put_if_present(:trusted_audiences, Keyword.get(opts, :trusted_audiences))
  end

  defp put_if_present(opts, _key, nil), do: opts
  defp put_if_present(opts, key, value), do: Keyword.put(opts, key, value)

  defp refresh_token_response(_config, token, opts) do
    with store when is_atom(store) and not is_nil(store) <- Keyword.get(opts, :refresh_store),
         {:ok, entry} <- store.get(Secret.hash(token)),
         true <- active_refresh?(entry, NumericDate.now(opts)) do
      rfc7662_refresh_response(entry)
    else
      _ -> nil
    end
  end

  # A refresh token is active only while it is explicitly unconsumed and
  # unexpired. Fail closed: an entry must carry `consumed: false` and an integer
  # `expires_at` in the future to be active, so a consumed (rotated) token - or
  # a malformed record missing `:consumed` - introspects as inactive.
  defp active_refresh?(%{consumed: false, expires_at: exp}, now) when is_integer(exp), do: exp > now
  defp active_refresh?(_entry, _now), do: false

  # Map the stored refresh-token record onto the RFC 7662 response members. The
  # token is opaque, but the core's own data contract (`Attesto.RefreshToken`
  # `build_data/3`, reproduced by the bundled stores' entry shape) carries the
  # subject, granted scope, presenting client, and optional DPoP binding, so the
  # safe RFC 7662 members are surfaced - both for a resource server and so an
  # `:authorize` policy can make a per-token decision (RFC 7662 §4 / RFC 9701
  # §5) rather than allow/deny every refresh token wholesale. Each member is
  # copied only when present and well-typed, so a custom store that does not
  # populate it (or omits `:data` entirely) simply yields the minimal response.
  defp rfc7662_refresh_response(entry) do
    data = entry_data(entry)

    %{"active" => true, "exp" => entry.expires_at}
    |> put_string("sub", data_member(data, :subject))
    |> put_string("client_id", data_member(data, :client_id))
    |> put_scope(data_member(data, :scope))
    |> put_cnf(data_member(data, :dpop_jkt))
  end

  defp entry_data(%{data: data}) when is_map(data), do: data
  defp entry_data(_entry), do: %{}

  # The bundled stores key `:data` with atoms (`Attesto.RefreshToken.build_data/3`);
  # a store that round-trips through a string-keyed encoding is read too.
  defp data_member(data, key), do: Map.get(data, key) || Map.get(data, Atom.to_string(key))

  defp put_string(response, _key, value) when not is_binary(value) or value == "", do: response
  defp put_string(response, key, value), do: Map.put(response, key, value)

  # RFC 7662 §2.2: `scope` is the space-delimited granted scope.
  defp put_scope(response, scope) when is_list(scope) do
    case Enum.filter(scope, &is_binary/1) do
      [] -> response
      strings -> Map.put(response, "scope", Enum.join(strings, " "))
    end
  end

  defp put_scope(response, _scope), do: response

  # RFC 7662 / RFC 9449: echo the DPoP binding so a resource server can verify a
  # sender-constrained refresh token, and report `token_type` accordingly.
  defp put_cnf(response, jkt) when is_binary(jkt) and jkt != "" do
    response |> Map.put("cnf", %{"jkt" => jkt}) |> Map.put("token_type", @dpop)
  end

  defp put_cnf(response, _jkt), do: response

  # Map the verified access-token claims onto the RFC 7662 response members,
  # carrying through only the members that are present. token_type reflects the
  # sender-constraint: a DPoP-bound token (cnf.jkt) is "DPoP", otherwise
  # "Bearer". The `cnf` is echoed so a resource server can verify the binding.
  defp rfc7662_response(claims) do
    %{"active" => true}
    |> copy(claims, "scope")
    |> copy(claims, "client_id")
    |> copy(claims, "sub")
    |> copy(claims, "aud")
    |> copy(claims, "iss")
    |> copy(claims, "exp")
    |> copy(claims, "iat")
    |> copy(claims, "jti")
    |> copy(claims, "cnf")
    |> Map.put("token_type", token_type(claims))
  end

  defp token_type(claims) do
    if is_binary(get_in(claims, ["cnf", "jkt"])), do: @dpop, else: @bearer
  end

  defp copy(response, claims, key) do
    case Map.get(claims, key) do
      nil -> response
      value -> Map.put(response, key, value)
    end
  end
end
