defmodule Attesto.Test.Factory do
  @moduledoc false
  # Test helpers: generate signing material, build a Config, and forge
  # DPoP proofs with JOSE so the engine can be exercised end to end.

  alias Attesto.Keystore.Static

  @doc "A fresh PKCS#1 RSA private-key PEM (the shape Attesto.Key expects)."
  def rsa_pem(bits \\ 2048) do
    priv = :public_key.generate_key({:rsa, bits, 65_537})
    :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, priv)])
  end

  @doc "A fresh EC signing key PEM (default P-256 -> ES256)."
  def ec_pem(curve \\ "P-256"), do: to_pem(JOSE.JWK.generate_key({:ec, curve}))

  @doc "A fresh Ed25519 (OKP) signing key PEM -> EdDSA."
  def ed_pem, do: to_pem(JOSE.JWK.generate_key({:okp, :Ed25519}))

  # JOSE.JWK.to_pem/1 returns {kty_meta, pem} for EC/OKP keys; take the PEM.
  defp to_pem(jwk) do
    case JOSE.JWK.to_pem(jwk) do
      {_meta, pem} when is_binary(pem) -> pem
      pem when is_binary(pem) -> pem
    end
  end

  @doc """
  Configure `Attesto.Keystore.Static` with `pem` and return a Config with
  two principal kinds (client, user). Installs and tears down the app env.
  """
  def config(pem, overrides \\ []) do
    # `:signing_alg` / `:key_algs` configure the Static keystore (not the
    # Config), e.g. an RSA key labelled PS256 or an EC/Ed key for ES256/EdDSA.
    {static_env, overrides} = Keyword.split(overrides, [:signing_alg, :key_algs])
    Application.put_env(:attesto, Static, [signing_pem: pem] ++ static_env)
    ExUnit.Callbacks.on_exit(fn -> Application.delete_env(:attesto, Static) end)

    Keyword.merge(
      [
        issuer: "https://api.example.com/",
        audience: "https://api.example.com/",
        keystore: Static,
        principal_kinds: [
          Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}]),
          Attesto.PrincipalKind.new("user", "usr_",
            required_claims: [
              {"act", :non_empty_string},
              {"sid", :non_empty_string},
              {"token_version", :non_neg_integer}
            ]
          )
        ]
      ],
      overrides
    )
    |> Attesto.Config.new()
  end

  @doc """
  Build a signed DPoP proof JWS and return `{proof, jkt}` where `jkt` is
  the RFC 7638 thumbprint of the proof's public key. Opts: `:htm`, `:htu`,
  `:iat`, `:jti`, `:ath`, `:alg` (default ES256 over a fresh P-256 key).
  """
  def dpop_proof(opts \\ []) do
    jwk = Keyword.get_lazy(opts, :jwk, fn -> JOSE.JWK.generate_key({:ec, "P-256"}) end)
    {_, public_map} = JOSE.JWK.to_public_map(jwk)

    header =
      %{"typ" => "dpop+jwt", "alg" => Keyword.get(opts, :alg, "ES256"), "jwk" => public_map}

    payload =
      %{
        "htm" => Keyword.get(opts, :htm, "POST"),
        "htu" => Keyword.get(opts, :htu, "https://api.example.com/oauth/token"),
        "iat" => Keyword.get(opts, :iat, System.system_time(:second)),
        "jti" => Keyword.get(opts, :jti, random_jti())
      }
      |> maybe_put("ath", Keyword.get(opts, :ath))

    {_, proof} = jwk |> JOSE.JWT.sign(header, payload) |> JOSE.JWS.compact()
    {proof, JOSE.JWK.thumbprint(jwk)}
  end

  @doc """
  A Config whose keystore is a *distinct* module (`ForeignKeystore`)
  holding `pem`, so it has signing material independent of the
  `Attesto.Keystore.Static` singleton. Use this to model a second issuer
  in the same VM (e.g. to prove a token from a foreign key fails
  signature verification under the primary config).
  """
  def foreign_config(pem, overrides \\ []) do
    Application.put_env(:attesto, __MODULE__.ForeignKeystore, signing_pem: pem)
    ExUnit.Callbacks.on_exit(fn -> Application.delete_env(:attesto, __MODULE__.ForeignKeystore) end)

    base = [
      issuer: "https://api.example.com/",
      audience: "https://api.example.com/",
      keystore: __MODULE__.ForeignKeystore,
      principal_kinds: [
        Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])
      ]
    ]

    base |> Keyword.merge(overrides) |> Attesto.Config.new()
  end

  defp maybe_put(map, _k, nil), do: map
  defp maybe_put(map, k, v), do: Map.put(map, k, v)

  defp random_jti, do: 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
end

defmodule Attesto.Test.Factory.ForeignKeystore do
  @moduledoc false
  @behaviour Attesto.Keystore

  @impl true
  def signing_pem, do: fetch()

  @impl true
  def verification_pems, do: [fetch()]

  defp fetch do
    :attesto
    |> Application.get_env(__MODULE__, [])
    |> Keyword.fetch!(:signing_pem)
  end
end
