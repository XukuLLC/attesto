defmodule Attesto.SignedIntrospection do
  @moduledoc """
  JWT response for OAuth 2.0 Token Introspection (RFC 9701).

  Builds the signed JWT an authorization server returns from its introspection
  endpoint (RFC 7662) when the caller requests
  `application/token-introspection+jwt`, giving the introspection response
  integrity and non-repudiation (FAPI 2.0 Message Signing §5.5).

  This is conn-free core: it turns the issuer/keystore on the `Attesto.Config`,
  the caller the response is addressed to, and the RFC 7662 introspection
  response map into a compact JWS. The transport layer (the introspection
  endpoint) decides - by content negotiation - whether to return the plain JSON
  response or this signed JWT; nothing here touches HTTP.

  ## JWT claims (RFC 9701 §5)

    * `iss` - REQUIRED, the authorization server's issuer identifier.
    * `aud` - REQUIRED, the entity that requested the introspection (the
      authenticated `client_id`).
    * `iat` - REQUIRED, the issuance time.
    * `token_introspection` - REQUIRED, a JSON object that is the RFC 7662
      introspection response (`active` plus, when active, the token's claims).

  The JOSE header `typ` is fixed to `"token-introspection+jwt"` (RFC 9701 §5),
  the explicit type that distinguishes a signed introspection response from any
  other JWT. Signing mirrors `Attesto.IDToken` / `Attesto.JARM`: the keystore's
  current signing key and algorithm, with the `kid` in the header, signed
  with that pinned algorithm (never `none`).
  """

  alias Attesto.{Config, JWS, Key, NumericDate, SigningAlg}

  # RFC 9701 §5: the explicit media type of a signed introspection response.
  @header_typ "token-introspection+jwt"

  # A signed introspection response is consumed immediately by the caller, so
  # the JWT is short-lived. `:lifetime`, when given, sets `exp`; by default no
  # `exp` is emitted (RFC 9701 does not require one).
  @type response :: %{optional(String.t()) => term()}

  @type opts :: [now: integer() | DateTime.t(), lifetime: pos_integer()]

  @doc """
  Build and sign the RFC 9701 introspection response JWT addressed to
  `audience`, wrapping the RFC 7662 `introspection_response`. Returns
  `{:ok, compact_jws}`.

  Options:

    * `:now` - the issuance time (integer Unix seconds or `DateTime`), for
      deterministic tests; defaults to the current time.
    * `:lifetime` - when given (seconds), adds an `exp` that many seconds after
      `iat`; omitted by default.
  """
  @spec response_jwt(Config.t(), String.t(), response(), opts()) ::
          {:ok, String.t()}
  def response_jwt(%Config{} = config, audience, introspection_response, opts \\ [])
      when is_binary(audience) and audience != "" and is_map(introspection_response) do
    now = NumericDate.now(opts)

    claims =
      %{
        "iss" => config.issuer,
        "aud" => audience,
        "iat" => now,
        "token_introspection" => introspection_response
      }
      |> put_exp(now, opts)

    pem = config.keystore.signing_pem()
    alg = SigningAlg.for_key(config.keystore, pem, signing?: true)
    header = %{"alg" => alg, "kid" => Key.kid(pem), "typ" => @header_typ}

    {:ok, JWS.sign_compact(pem, header, claims)}
  end

  @doc "The JOSE header `typ` a signed introspection response carries (RFC 9701 §5)."
  @spec header_typ() :: String.t()
  def header_typ, do: @header_typ

  defp put_exp(claims, now, opts) do
    case Keyword.get(opts, :lifetime) do
      n when is_integer(n) and n > 0 -> Map.put(claims, "exp", now + n)
      _ -> claims
    end
  end
end
