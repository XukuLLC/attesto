defmodule Attesto.SignedUserInfo do
  @moduledoc """
  Signed UserInfo Response (OpenID Connect Core 1.0 §5.3.2).

  A client that registered `userinfo_signed_response_alg` receives the
  UserInfo claims as a JWT (`application/jwt`) and not as a JSON object. §5.3.2
  requires a signed response to carry `iss` and `aud`: the issuer identifier
  and the client the response is for.

  This is conn-free core: it turns the issuer and keystore on the
  `Attesto.Config`, the client, and the UserInfo claims into a compact JWS.
  The UserInfo endpoint decides whether a given client gets the signed form.

  Signing uses the keystore's current signing key and its algorithm, with the
  `kid` in the header, as `Attesto.IDToken` does. The provider signs with one
  key, so a client is served only when the algorithm it registered is that
  key's algorithm; `response_jwt/4` returns `{:error, :unsupported_alg}`
  otherwise, including for `none`. Encrypted UserInfo responses
  (`userinfo_encrypted_response_alg`) are not implemented.
  """

  alias Attesto.{Config, JWS, OpenIDDiscovery}

  @doc """
  The algorithms advertised for signed UserInfo responses, for the
  `userinfo_signing_alg_values_supported` metadata member: the same list as
  `id_token_signing_alg_values_supported`
  (`Attesto.OpenIDDiscovery.signing_algs/1`). Takes the configuration or its
  keystore module.

  A response is signed with the current signing key, so after a key rotation
  to another algorithm a client registered for the old one is refused by
  `response_jwt/4` until it registers the new one.
  """
  @spec signing_algs(Config.t() | module()) :: [String.t()]
  def signing_algs(config_or_keystore), do: OpenIDDiscovery.signing_algs(config_or_keystore)

  @doc """
  Sign `claims` as the UserInfo response for `audience` (the `client_id`),
  using `alg`, the algorithm that client registered.

  `iss` and `aud` are set here and override any such member in `claims`.
  Returns `{:ok, compact_jws}` or `{:error, :unsupported_alg}` when `alg` is
  not the current signing key's algorithm.
  """
  @spec response_jwt(Config.t(), String.t(), map(), String.t()) :: {:ok, String.t()} | {:error, :unsupported_alg}
  def response_jwt(%Config{} = config, audience, claims, alg)
      when is_binary(audience) and audience != "" and is_map(claims) do
    context = JWS.current_signing_context(config.keystore)

    if alg == context.alg do
      claims = Map.merge(claims, %{"iss" => config.issuer, "aud" => audience})
      {:ok, JWS.sign_current(config.keystore, claims, signing_context: context)}
    else
      {:error, :unsupported_alg}
    end
  end
end
