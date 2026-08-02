defmodule Attesto.LogoutToken do
  @moduledoc """
  Mint OpenID Connect Back-Channel Logout `logout_token`s
  (OpenID Connect Back-Channel Logout 1.0 §2.4).

  A logout token is the signed JWT an OP POSTs to a Relying Party's
  `backchannel_logout_uri` to tell it a session has ended. It is a distinct
  artifact from the `Attesto.IDToken` and `Attesto.Token` this library also
  mints: its JOSE header `typ` is the dedicated `logout+jwt` (so an RP can
  reject anything else presented at its logout endpoint), and it carries an
  `events` claim naming the back-channel-logout event rather than identity
  or authorization claims.

  Like `Attesto.IDToken`, minting is pure: it reads only the `Attesto.Config`
  passed in and signs through the same keystore/`kid` path. The algorithm is
  bound to trusted keystore metadata or the signing key's type and curve by
  `Attesto.SigningAlg`; the protected header records that resolved algorithm
  but never supplies its policy. The JOSE call funnels through the shared
  internal JWS signer.

  ## Claims (Back-Channel Logout 1.0 §2.4)

  Every minted logout token carries:

    * `iss` - the configured issuer.
    * `aud` - the OAuth `client_id` of the Relying Party (as in an ID Token).
    * `iat` - issued-at, unix seconds.
    * `jti` - a unique identifier, so an RP can detect a replayed token.
    * `events` - a JSON object with the single member
      `"#{"http://schemas.openid.net/event/backchannel-logout"}"` mapped to an
      empty object, identifying this as a back-channel logout request.

  At least one of:

    * `sub` - the subject whose session(s) ended.
    * `sid` - the session id that ended (the same value that rode in the ID
      Token's `sid` claim).

  Per §2.4 a logout token **MUST NOT** contain a `nonce` claim; this module
  never emits one. An `exp` is included with a deliberately short lifetime so
  a captured token cannot be replayed indefinitely (the spec leaves `exp`
  optional; including a short one is strictly safer for a conforming RP).

  ## Targeting `sub` vs `sid`

  Back-Channel Logout 1.0 §2.4 requires a logout token to identify the
  session by `sub`, `sid`, or both, and an RP advertises via
  `backchannel_logout_session_required` whether it needs `sid`. Supply both
  when known; supply `:sid` for an RP that requires session-scoped logout and
  `:sub` for one that logs out every session for the subject.
  """

  alias Attesto.Config
  alias Attesto.Key
  alias Attesto.NumericDate
  alias Attesto.SigningAlg

  # The dedicated logout-token media type (Back-Channel Logout 1.0 §2.4): an
  # RP rejects a plain ID Token (`typ: "JWT"`) presented at its logout endpoint.
  @header_typ "logout+jwt"

  # Back-Channel Logout 1.0 §2.4: the `events` claim names this event URI.
  @event_uri "http://schemas.openid.net/event/backchannel-logout"

  # Logout tokens are consumed immediately on receipt; keep the validity window
  # short so a captured token has a narrow replay horizon. May only be shortened.
  @default_lifetime_seconds 120

  @type mint_opts :: [
          {:sub, String.t()}
          | {:sid, String.t()}
          | {:now, DateTime.t() | non_neg_integer()}
          | {:lifetime, pos_integer()}
          | {:jti, String.t()}
        ]

  @type mint_error :: :invalid_client_id | :missing_subject_identifier

  @doc "The JOSE header `typ` logout tokens carry: `\"logout+jwt\"`."
  @spec header_typ() :: String.t()
  def header_typ, do: @header_typ

  @doc "The back-channel-logout `events` URI (Back-Channel Logout 1.0 §2.4)."
  @spec event_uri() :: String.t()
  def event_uri, do: @event_uri

  @doc """
  Mint a signed Back-Channel Logout token addressed to the Relying Party
  identified by `client_id` (which becomes `aud`, as in an ID Token).

  Options:

    * `:sub` - the subject whose session ended.
    * `:sid` - the session id that ended (matches the ID Token `sid`).
      At least one of `:sub` / `:sid` MUST be supplied
      (`:missing_subject_identifier` otherwise).
    * `:jti` - override the generated unique identifier (a fresh CSPRNG value
      is used otherwise).
    * `:now` - `DateTime` or unix-seconds clock override. Defaults to now.
    * `:lifetime` - positive seconds; may only *shorten* the short default.

  Returns `{:ok, logout_token}` (compact JWS) or `{:error, reason}`.
  """
  @spec mint(Config.t(), String.t(), mint_opts()) :: {:ok, String.t()} | {:error, mint_error()}
  def mint(config, client_id, opts \\ [])

  def mint(%Config{} = config, client_id, opts) when is_binary(client_id) and is_list(opts) do
    with :ok <- check_non_empty(client_id, :invalid_client_id),
         {:ok, identifiers} <- subject_identifiers(opts) do
      iat = NumericDate.now(opts)
      lifetime = lifetime_seconds(opts)
      pem = config.keystore.signing_pem()
      alg = SigningAlg.for_key(config.keystore, pem, signing?: true)

      claims =
        %{
          "iss" => config.issuer,
          "aud" => client_id,
          "iat" => iat,
          "exp" => iat + lifetime,
          "jti" => jti(opts),
          "events" => %{@event_uri => %{}}
        }
        |> Map.merge(identifiers)

      {:ok, sign(pem, claims, alg)}
    end
  end

  def mint(%Config{}, _client_id, _opts), do: {:error, :invalid_client_id}

  # ----- internal -----

  # §2.4: a logout token MUST contain sub, sid, or both. Neither is a caller
  # bug — there is no session to identify.
  defp subject_identifiers(opts) do
    identifiers =
      %{}
      |> put_identifier("sub", Keyword.get(opts, :sub))
      |> put_identifier("sid", Keyword.get(opts, :sid))

    if map_size(identifiers) == 0,
      do: {:error, :missing_subject_identifier},
      else: {:ok, identifiers}
  end

  defp put_identifier(acc, _key, nil), do: acc
  defp put_identifier(acc, _key, ""), do: acc
  defp put_identifier(acc, key, value) when is_binary(value), do: Map.put(acc, key, value)
  defp put_identifier(acc, _key, _value), do: acc

  defp jti(opts) do
    case Keyword.get(opts, :jti) do
      jti when is_binary(jti) and jti != "" -> jti
      _ -> 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    end
  end

  defp sign(pem, claims, alg) do
    Attesto.JWS.sign_compact(pem, jose_header(pem, alg), claims)
  end

  defp jose_header(pem, alg) do
    %{"alg" => alg, "kid" => Key.kid(pem), "typ" => @header_typ}
  end

  defp lifetime_seconds(opts) do
    case Keyword.get(opts, :lifetime) do
      n when is_integer(n) and n > 0 and n <= @default_lifetime_seconds -> n
      _ -> @default_lifetime_seconds
    end
  end

  defp check_non_empty(value, _error) when is_binary(value) and value != "", do: :ok
  defp check_non_empty(_value, error), do: {:error, error}
end
