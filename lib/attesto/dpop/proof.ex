defmodule Attesto.DPoP.Proof do
  @moduledoc """
  Builds signed DPoP proof JWTs as defined by RFC 9449 section 4.

  The proof binds a public key to one HTTP method and target URI. Query and
  fragment components are excluded from the `htu` claim, and an access token
  can be bound through the `ath` claim for protected-resource requests.

  This module is the client-side counterpart to `Attesto.DPoP.verify_proof/2`.
  It accepts a private `%JOSE.JWK{}` or JWK map and embeds only its public
  members in the protected header.
  """

  alias Attesto.{DPoP, JWS, SigningAlg}

  @proof_typ "dpop+jwt"
  @max_jti_length 256
  @max_nonce_length 4_096
  @jti_bytes 16
  @signing_failure_message "signing operation failed"

  @rsa_algs ~w(RS256 RS384 RS512 PS256 PS384 PS512)
  @ec_algs %{"P-256" => "ES256", "P-384" => "ES384", "P-521" => "ES512"}

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:access_token, String.t()}
          | {:nonce, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, DateTime.t() | non_neg_integer()}
          | {:jti, String.t()}

  @type error ::
          :invalid_key
          | :invalid_kid
          | :invalid_htm
          | :invalid_htu
          | :invalid_access_token
          | :invalid_nonce
          | :invalid_time
          | :invalid_jti
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @doc """
  Builds a signed DPoP proof for `htm` and `htu`.

  The target must be an absolute HTTPS URI without userinfo. Its query and
  fragment are stripped before the `htu` claim is signed. Use `:access_token`
  to add `ath`, and `:nonce` to echo a server-issued DPoP nonce.

  `:alg` must be an asymmetric algorithm accepted by `Attesto.DPoP`; when it
  is omitted, the key's declared `alg` is used before falling back to key-type
  inference. An explicit algorithm cannot override a conflicting key
  declaration. The optional `:kid` follows the same precedence rule: an
  explicit value wins, otherwise the key's declared `kid` is used.
  """
  @spec build(jwk(), String.t(), String.t(), [build_opt()]) ::
          {:ok, String.t()} | {:error, error()}
  def build(jwk, htm, htu, opts \\ [])

  def build(jwk, htm, htu, opts) when is_list(opts) do
    with {:ok, jose_jwk} <- normalize_key(jwk),
         {:ok, method} <- normalize_htm(htm),
         {:ok, uri} <- normalize_htu(htu),
         {:ok, now} <- validate_now(opts),
         {:ok, jti} <- validate_jti(opts),
         {:ok, alg} <- resolve_alg(jose_jwk, opts),
         {:ok, kid} <- resolve_kid(jose_jwk, opts),
         {:ok, access_token_hash} <- access_token_hash(opts),
         {:ok, nonce} <- nonce(opts) do
      claims =
        %{"htm" => method, "htu" => uri, "iat" => now, "jti" => jti}
        |> put_optional("ath", access_token_hash)
        |> put_optional("nonce", nonce)

      header =
        %{"alg" => alg, "typ" => @proof_typ, "jwk" => public_jwk(jose_jwk)}
        |> put_optional("kid", kid)

      sign(jose_jwk, header, claims)
    end
  end

  @doc false
  @spec resolve_alg(JOSE.JWK.t(), keyword()) ::
          {:ok, String.t()}
          | {:error, :unsupported_alg | :unsupported_key | {:signing_failed, String.t()}}
  def resolve_alg(%JOSE.JWK{} = jose_jwk, opts) when is_list(opts) do
    with {:ok, declared_alg} <- declared_alg(jose_jwk) do
      case Keyword.fetch(opts, :alg) do
        :error -> resolve_default_alg(jose_jwk, declared_alg)
        {:ok, nil} -> resolve_default_alg(jose_jwk, declared_alg)
        {:ok, alg} -> resolve_explicit_alg(jose_jwk, alg, declared_alg)
      end
    end
  end

  defp normalize_key(%JOSE.JWK{} = jwk), do: {:ok, jwk}

  defp normalize_key(map) when is_map(map) do
    {:ok, JOSE.JWK.from_map(map)}
  rescue
    _error -> {:error, :invalid_key}
  catch
    _kind, _reason -> {:error, :invalid_key}
  end

  defp normalize_key(_other), do: {:error, :invalid_key}

  defp normalize_htm(htm) when is_binary(htm) do
    case String.trim(htm) do
      "" -> {:error, :invalid_htm}
      method -> {:ok, String.upcase(method)}
    end
  rescue
    _error -> {:error, :invalid_htm}
  end

  defp normalize_htm(_other), do: {:error, :invalid_htm}

  # RFC 9449 section 4.2 excludes query and fragment from `htu`. Validate the
  # complete source first so malformed percent escapes cannot hide in a
  # component that is subsequently removed.
  defp normalize_htu(htu) when is_binary(htu) do
    with false <- Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, htu),
         {:ok, %Elixir.URI{} = parsed} <- Elixir.URI.new(htu),
         normalized =
           Elixir.URI.to_string(%{
             parsed
             | path: Attesto.URI.normalize_path(parsed.path),
               query: nil,
               fragment: nil
           }),
         true <- Attesto.URI.https_identifier?(normalized) do
      {:ok, normalized}
    else
      _other -> {:error, :invalid_htu}
    end
  rescue
    _error -> {:error, :invalid_htu}
  end

  defp normalize_htu(_other), do: {:error, :invalid_htu}

  defp validate_now(opts) do
    case Keyword.fetch(opts, :now) do
      :error -> {:ok, System.system_time(:second)}
      {:ok, %DateTime{} = now} -> validate_unix_time(DateTime.to_unix(now, :second))
      {:ok, now} when is_integer(now) and now >= 0 -> {:ok, now}
      {:ok, _invalid} -> {:error, :invalid_time}
    end
  end

  defp validate_unix_time(now) when is_integer(now) and now >= 0, do: {:ok, now}
  defp validate_unix_time(_invalid), do: {:error, :invalid_time}

  defp validate_jti(opts) do
    case Keyword.fetch(opts, :jti) do
      :error -> {:ok, random_jti()}
      {:ok, jti} when is_binary(jti) and byte_size(jti) in 1..@max_jti_length -> {:ok, jti}
      {:ok, _invalid} -> {:error, :invalid_jti}
    end
  end

  defp declared_alg(jose_jwk) do
    jose_jwk
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> Map.fetch("alg")
    |> case do
      :error -> {:ok, nil}
      {:ok, alg} when is_binary(alg) -> if alg in DPoP.allowed_algs(), do: {:ok, alg}, else: {:error, :unsupported_alg}
      {:ok, _invalid} -> {:error, :unsupported_alg}
    end
  rescue
    _error -> {:error, :unsupported_key}
  end

  defp resolve_default_alg(jose_jwk, nil) do
    alg = SigningAlg.infer(jose_jwk)

    if alg in DPoP.allowed_algs() and compatible?(alg, jose_jwk),
      do: {:ok, alg},
      else: {:error, :unsupported_key}
  rescue
    _error -> {:error, :unsupported_key}
  end

  defp resolve_default_alg(jose_jwk, alg), do: validate_alg_for_key(jose_jwk, alg)

  defp resolve_explicit_alg(jose_jwk, alg, declared_alg) when is_binary(alg) and declared_alg in [nil, alg] do
    if alg in DPoP.allowed_algs(),
      do: validate_alg_for_key(jose_jwk, alg),
      else: {:error, :unsupported_alg}
  end

  defp resolve_explicit_alg(_jose_jwk, _alg, _declared_alg), do: {:error, :unsupported_alg}

  defp validate_alg_for_key(jose_jwk, alg) do
    if compatible?(alg, jose_jwk),
      do: {:ok, alg},
      else: {:error, {:signing_failed, @signing_failure_message}}
  rescue
    _error -> {:error, {:signing_failed, @signing_failure_message}}
  end

  defp compatible?(alg, jose_jwk) do
    fields = jose_jwk |> JOSE.JWK.to_public_map() |> elem(1)

    case fields do
      %{"kty" => "RSA"} -> alg in @rsa_algs
      %{"kty" => "EC", "crv" => curve} -> Map.get(@ec_algs, curve) == alg
      %{"kty" => "OKP", "crv" => "Ed25519"} -> alg in ["EdDSA", "Ed25519"]
      %{"kty" => "OKP", "crv" => "Ed448"} -> alg in ["EdDSA", "Ed448"]
      _other -> false
    end
  end

  defp resolve_kid(jose_jwk, opts) do
    case Keyword.fetch(opts, :kid) do
      {:ok, explicit} -> validate_present_kid(explicit)
      :error -> resolve_embedded_kid(jose_jwk)
    end
  end

  defp resolve_embedded_kid(jose_jwk) do
    jose_jwk
    |> JOSE.JWK.to_map()
    |> elem(1)
    |> Map.fetch("kid")
    |> case do
      :error -> {:ok, nil}
      {:ok, value} -> validate_present_kid(value)
    end
  rescue
    _error -> {:error, :invalid_kid}
  end

  defp validate_present_kid(value) when is_binary(value) and value != "", do: {:ok, value}
  defp validate_present_kid(_invalid), do: {:error, :invalid_kid}

  defp access_token_hash(opts) do
    case Keyword.fetch(opts, :access_token) do
      :error -> {:ok, nil}
      {:ok, token} when is_binary(token) and token != "" -> {:ok, DPoP.compute_ath(token)}
      {:ok, _invalid} -> {:error, :invalid_access_token}
    end
  end

  defp nonce(opts) do
    case Keyword.fetch(opts, :nonce) do
      :error -> {:ok, nil}
      {:ok, nonce} when is_binary(nonce) and byte_size(nonce) in 1..@max_nonce_length -> {:ok, nonce}
      {:ok, _invalid} -> {:error, :invalid_nonce}
    end
  end

  defp public_jwk(jose_jwk), do: jose_jwk |> JOSE.JWK.to_public_map() |> elem(1)

  defp sign(jose_jwk, %{"alg" => "PS" <> _} = header, claims) do
    {:ok, JWS.sign_compact_jwk(jose_jwk, header, claims)}
  rescue
    _error -> {:error, {:signing_failed, @signing_failure_message}}
  catch
    _kind, _reason -> {:error, {:signing_failed, @signing_failure_message}}
  end

  defp sign(jose_jwk, header, claims) do
    {_protected, compact} = jose_jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    {:ok, compact}
  rescue
    _error -> {:error, {:signing_failed, @signing_failure_message}}
  catch
    _kind, _reason -> {:error, {:signing_failed, @signing_failure_message}}
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp random_jti, do: @jti_bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
end
