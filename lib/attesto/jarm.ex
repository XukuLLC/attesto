defmodule Attesto.JARM do
  @moduledoc """
  JWT Secured Authorization Response Mode (JARM).

  Builds the signed JWT an authorization server returns to a client as the
  single `response` parameter when a JWT response mode (`jwt`, `query.jwt`,
  `fragment.jwt`, `form_post.jwt`) is requested, giving the authorization
  response non-repudiation and integrity (FAPI 2.0 Message Signing §5.4).

  This is conn-free core: it turns the issuer/keystore on the `Attesto.Config`,
  the client identifier, and a map of authorization-response parameters (the
  `code`/`state`/`iss` of a success, or the `error`/`error_description`/`state`
  of a failure) into a compact JWS. The transport layer (the authorization
  endpoint) decides the response mode and how the resulting JWT is delivered
  (redirect query/fragment or auto-submitting form); nothing here touches HTTP.

  ## JWT claims (JARM §2.1)

    * `iss` - REQUIRED, the authorization server's issuer identifier.
    * `aud` - REQUIRED, the client the response is addressed to (`client_id`).
    * `exp` - REQUIRED, expiration; the response is short-lived.
    * `iat` - the issuance time.
    * every supplied authorization-response parameter, verbatim, as a top-level
      claim (`code`, `state`, `iss`-echo for success; `error`,
      `error_description`, `error_uri`, `state` for failure).

  Signing mirrors `Attesto.IDToken`: the keystore's current signing key and its
  algorithm (`Attesto.SigningAlg.for_key/3`), with the `kid` in the JOSE header,
  signed with that pinned algorithm (never `none`).
  """

  alias Attesto.{Config, JWS, Key, SigningAlg}

  # JARM responses are consumed immediately by the client on the redirect, so
  # the JWT is short-lived. `:lifetime` may only shorten this default.
  @default_lifetime_seconds 600

  @type response_params :: %{optional(String.t()) => String.t() | nil}

  @type opts :: [now: integer() | DateTime.t(), lifetime: pos_integer()]

  @doc """
  Build and sign the JARM response JWT for `client_id`, carrying `params`.

  `params` is the authorization-response parameter map; `nil` values are
  dropped (an absent `state`/`error_uri` is not advertised). Returns
  `{:ok, compact_jws}`.

  Options:

    * `:now` - the issuance time (integer Unix seconds or `DateTime`), for
      deterministic tests; defaults to the current time.
    * `:lifetime` - the JWT lifetime in seconds; may only shorten the
      `#{@default_lifetime_seconds}`-second default.
  """
  @spec response_jwt(Config.t(), String.t(), response_params(), opts()) ::
          {:ok, String.t()}
  def response_jwt(%Config{} = config, client_id, params, opts \\ [])
      when is_binary(client_id) and client_id != "" and is_map(params) do
    now = unix_now(opts)

    claims =
      params
      |> drop_nil()
      |> stringify_keys()
      |> Map.merge(%{
        "iss" => config.issuer,
        "aud" => client_id,
        "iat" => now,
        "exp" => now + lifetime_seconds(opts)
      })

    pem = config.keystore.signing_pem()
    alg = SigningAlg.for_key(config.keystore, pem, signing?: true)
    header = %{"alg" => alg, "kid" => Key.kid(pem)}

    {:ok, JWS.sign_compact(pem, header, claims)}
  end

  defp drop_nil(params) do
    params
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  # The reserved claims (`iss`, `aud`, `iat`, `exp`) are set by the merge below,
  # and a string key there overwrites a caller's string key of the same name -
  # the server value wins. An *atom* key (`:iss`) is a distinct map key, so it
  # would survive the merge and serialize to the same JSON member name as the
  # server's `"iss"`, producing a duplicate member whose value a lenient JSON
  # parser might prefer. Collapse every atom key onto its string form first so
  # the merge is authoritative and the JWT can never carry a duplicate claim.
  # (`params`'s contract is string keys; this hardens the public core against a
  # caller that mixes in atoms rather than trusting the contract.)
  defp stringify_keys(params) do
    Map.new(params, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} -> {key, value}
    end)
  end

  # `:lifetime` may only shorten the default - a larger value (or a
  # non-positive / non-integer) falls back to the default.
  defp lifetime_seconds(opts) do
    case Keyword.get(opts, :lifetime) do
      n when is_integer(n) and n > 0 and n <= @default_lifetime_seconds -> n
      _ -> @default_lifetime_seconds
    end
  end

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      nil -> DateTime.utc_now() |> DateTime.to_unix(:second)
      n when is_integer(n) -> n
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
    end
  end
end
