defmodule Attesto.Federation.EntityStatement do
  @moduledoc """
  Build and verify OpenID Federation 1.0 Entity Statements.

  The module is transport-independent. An Entity Configuration produced by
  `entity_configuration/3` is suitable for serving from the
  `/.well-known/openid-federation` endpoint, but endpoint routing and HTTP are
  deliberately left to the host application.
  """

  alias Attesto.Federation.MetadataPolicy
  alias Attesto.{JWS, Key, NumericDate, SigningAlg, Thumbprint}

  @typ "entity-statement+jwt"
  @default_lifetime_seconds 3600
  @private_jwk_members ~w(d p q dp dq qi oth k)

  @type signing_key :: module() | String.t()
  @type verify_error ::
          :invalid_entity_statement
          | :invalid_typ
          | :invalid_alg
          | :unsupported_critical_header
          | :invalid_signature
          | :not_yet_valid
          | :expired

  @doc """
  Build and sign an Entity Statement.

  `claims` must provide string `iss` and `sub` values. Missing `iat`, `exp`,
  and `jwks` values default to the selected signing key's current time,
  one-hour lifetime, and public JWK respectively. A Subordinate Statement
  normally supplies its subject's `jwks` explicitly.

  Options include `:now`, `:iat`, `:exp`, `:lifetime` (with
  `:lifetime_seconds` accepted as an alias), `:jwks`, and, for a PEM key,
  `:alg`.
  """
  @spec build(signing_key(), map(), keyword()) :: String.t()
  def build(keystore_or_pem, claims, opts \\ [])

  def build(keystore_or_pem, claims, opts) when is_map(claims) and is_list(opts) do
    context = signing_context(keystore_or_pem, opts)
    statement_claims = complete_claims(claims, context, opts)
    validate_build_claims!(statement_claims, context)
    sign(context, statement_claims)
  end

  def build(_keystore_or_pem, claims, opts) do
    raise ArgumentError,
          "EntityStatement.build/3 expects a string-keyed claims map and keyword options; " <>
            "got #{inspect(claims)} and #{inspect(opts)}"
  end

  @doc """
  Build a self-issued Entity Configuration (`iss == sub`).

  `:metadata`, `:authority_hints`, and `:trust_marks` are copied into the
  configuration when present. The common signing and time options accepted by
  `build/3` are also supported.
  """
  @spec entity_configuration(signing_key(), String.t(), keyword()) :: String.t()
  def entity_configuration(keystore_or_pem, entity_id, opts \\ [])

  def entity_configuration(keystore_or_pem, entity_id, opts) when is_binary(entity_id) and is_list(opts) do
    claims =
      %{"iss" => entity_id, "sub" => entity_id}
      |> put_option("metadata", opts, :metadata)
      |> put_option("authority_hints", opts, :authority_hints)
      |> put_option("trust_marks", opts, :trust_marks)

    build(keystore_or_pem, claims, opts)
  end

  def entity_configuration(_keystore_or_pem, entity_id, opts) do
    raise ArgumentError,
          "EntityStatement.entity_configuration/3 expects an entity identifier and keyword options; " <>
            "got #{inspect(entity_id)} and #{inspect(opts)}"
  end

  @doc """
  Verify an Entity Statement with trusted issuer keys.

  Signature algorithm and `kid` selection are pinned to the protected header,
  the `typ` header is mandatory, and all required claims and NumericDate
  values are validated. `:accepted_algs` defaults to all asymmetric algorithms
  supported by Attesto; `:now`, `:leeway`, `:issuer`, and `:subject` may also be
  supplied.
  """
  @spec verify(String.t(), map() | [map()], keyword()) ::
          {:ok, map()} | {:error, verify_error()}
  def verify(jwt, jwks, opts \\ [])

  def verify(jwt, jwks, opts) when is_binary(jwt) and is_list(opts) do
    with {:ok, header} <- peek_header(jwt),
         :ok <- check_header(header, opts),
         :ok <- validate_trusted_keys(jwks),
         {:ok, claims} <- verify_signature(jwt, header, jwks, opts),
         :ok <- validate_claims(claims, opts) do
      {:ok, claims}
    end
  end

  def verify(_jwt, _jwks, _opts), do: {:error, :invalid_entity_statement}

  @doc """
  Verify a self-issued Entity Configuration against its embedded public keys.

  The embedded keys are untrusted until the compact JWS verifies; after that,
  `iss == sub` and Entity Configuration-only claim placement are enforced.
  """
  @spec verify_self_signed(String.t(), keyword()) ::
          {:ok, map()} | {:error, verify_error()}
  def verify_self_signed(jwt, opts \\ [])

  def verify_self_signed(jwt, opts) when is_binary(jwt) and is_list(opts) do
    with {:ok, untrusted_claims} <- peek_claims(jwt),
         %{"keys" => keys} = jwks when is_list(keys) <- Map.get(untrusted_claims, "jwks"),
         {:ok, claims} <- verify(jwt, jwks, opts),
         true <- self_issued?(claims) do
      {:ok, claims}
    else
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_entity_statement}
    end
  end

  def verify_self_signed(_jwt, _opts), do: {:error, :invalid_entity_statement}

  defp signing_context(keystore, _opts) when is_atom(keystore) do
    keystore
    |> JWS.current_signing_context()
    |> Map.put(:keystore, keystore)
  end

  defp signing_context(pem, opts) when is_binary(pem) do
    jwk = Key.signing_jwk(pem)
    alg = Keyword.get(opts, :alg, SigningAlg.infer(jwk))
    alg = SigningAlg.validate_for_key!(alg, jwk)
    {:ok, kid} = Thumbprint.of_jwk(jwk)
    %{pem: pem, jwk: jwk, alg: alg, kid: kid}
  end

  defp signing_context(other, _opts) do
    raise ArgumentError,
          "expected a keystore module or private signing-key PEM; got #{inspect(other)}"
  end

  defp complete_claims(claims, context, opts) do
    ensure_string_keyed!(claims)
    now = NumericDate.now(opts, default: :system)
    iat = Map.get(claims, "iat", Keyword.get(opts, :iat, now))
    lifetime = lifetime_seconds!(opts)
    exp = Map.get(claims, "exp", Keyword.get(opts, :exp, default_exp(iat, lifetime)))
    jwks = Map.get(claims, "jwks", Keyword.get(opts, :jwks, public_jwks(context)))

    claims
    |> Map.put("iat", iat)
    |> Map.put("exp", exp)
    |> Map.put("jwks", jwks)
  end

  defp default_exp(iat, lifetime) when is_integer(iat), do: iat + lifetime
  defp default_exp(_iat, _lifetime), do: nil

  defp lifetime_seconds!(opts) do
    lifetime = Keyword.get(opts, :lifetime, Keyword.get(opts, :lifetime_seconds, @default_lifetime_seconds))

    case lifetime do
      value when is_integer(value) and value > 0 -> value
      value -> raise ArgumentError, ":lifetime must be a positive integer; got #{inspect(value)}"
    end
  end

  defp public_jwks(%{jwk: jwk, alg: alg, kid: kid}) do
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)
    %{"keys" => [Map.merge(public, %{"alg" => alg, "kid" => kid})]}
  end

  defp sign(%{keystore: keystore} = context, claims) do
    JWS.sign_current(keystore, claims, signing_context: context, typ: @typ)
  end

  defp sign(%{pem: pem, alg: alg, kid: kid}, claims) do
    JWS.sign_compact(pem, %{"alg" => alg, "kid" => kid, "typ" => @typ}, claims)
  end

  defp validate_build_claims!(claims, context) do
    with :ok <- validate_required_claims(claims),
         :ok <- validate_claim_placement(claims),
         :ok <- validate_optional_claims(claims),
         :ok <- validate_self_signing_key(claims, context) do
      :ok
    else
      {:error, _reason} ->
        raise ArgumentError, "claims are not a valid OpenID Federation Entity Statement"
    end
  end

  defp validate_self_signing_key(%{"iss" => entity, "sub" => entity, "jwks" => %{"keys" => keys}}, %{kid: kid}) do
    if Enum.any?(keys, &(Map.get(&1, "kid") == kid)),
      do: :ok,
      else: {:error, :invalid_entity_statement}
  end

  defp validate_self_signing_key(_claims, _context), do: :ok

  defp ensure_string_keyed!(claims) do
    if !Enum.all?(Map.keys(claims), &is_binary/1) do
      raise ArgumentError, "Entity Statement claims must use string keys"
    end
  end

  defp put_option(claims, claim, opts, option) do
    case Keyword.fetch(opts, option) do
      {:ok, value} -> Map.put(claims, claim, value)
      :error -> claims
    end
  end

  defp peek_header(jwt) do
    case JWS.peek_json(jwt, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :invalid_entity_statement}
    end
  end

  defp peek_claims(jwt) do
    case JWS.peek_json(jwt, :payload) do
      {:ok, claims} -> {:ok, claims}
      {:error, _reason} -> {:error, :invalid_entity_statement}
    end
  end

  defp check_header(header, opts) do
    with :ok <- check_typ(header),
         :ok <- check_critical_header(header),
         :ok <- check_alg(header, opts) do
      check_kid(header)
    end
  end

  defp check_typ(%{"typ" => @typ}), do: :ok
  defp check_typ(_header), do: {:error, :invalid_typ}

  defp check_critical_header(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp check_alg(%{"alg" => alg}, opts) when is_binary(alg) do
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())

    if alg != "none" and alg in SigningAlg.allowed() and is_list(accepted_algs) and alg in accepted_algs,
      do: :ok,
      else: {:error, :invalid_alg}
  end

  defp check_alg(_header, _opts), do: {:error, :invalid_alg}

  defp check_kid(%{"kid" => kid}) when is_binary(kid) and kid != "", do: :ok
  defp check_kid(_header), do: {:error, :invalid_entity_statement}

  defp verify_signature(jwt, header, jwks, opts) do
    candidates =
      JWS.verification_candidates(jwks,
        kid: Map.fetch!(header, "kid"),
        accepted_algs: Keyword.get(opts, :accepted_algs, SigningAlg.allowed()),
        malformed_key: :reject_set
      )

    JWS.verify_strict(jwt, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :halt,
      malformed_error: :invalid_entity_statement,
      claims_map?: true
    )
  end

  defp validate_claims(claims, opts) do
    with :ok <- validate_required_claims(claims),
         :ok <- validate_claim_placement(claims),
         :ok <- validate_optional_claims(claims),
         :ok <- validate_expected_entity(claims, opts) do
      validate_temporal_claims(claims, opts)
    end
  end

  defp validate_required_claims(claims) do
    with true <- entity_identifier?(Map.get(claims, "iss")),
         true <- entity_identifier?(Map.get(claims, "sub")),
         true <- NumericDate.valid?(Map.get(claims, "iat"), non_negative: true),
         true <- NumericDate.valid?(Map.get(claims, "exp"), non_negative: true),
         true <- Map.fetch!(claims, "exp") > Map.fetch!(claims, "iat"),
         true <- valid_embedded_jwks?(Map.get(claims, "jwks")) do
      :ok
    else
      _other -> {:error, :invalid_entity_statement}
    end
  rescue
    _ -> {:error, :invalid_entity_statement}
  end

  defp validate_claim_placement(%{"iss" => entity, "sub" => entity} = claims) do
    if Map.has_key?(claims, "metadata_policy") or Map.has_key?(claims, "metadata_policy_crit") or
         Map.has_key?(claims, "constraints") do
      {:error, :invalid_entity_statement}
    else
      :ok
    end
  end

  defp validate_claim_placement(claims) do
    if Map.has_key?(claims, "authority_hints") or Map.has_key?(claims, "trust_marks") do
      {:error, :invalid_entity_statement}
    else
      :ok
    end
  end

  defp validate_optional_claims(claims) do
    with :ok <- validate_metadata(Map.get(claims, "metadata", :absent)),
         :ok <- validate_metadata_policy(Map.get(claims, "metadata_policy", :absent)),
         :ok <- validate_authority_hints(Map.get(claims, "authority_hints", :absent)),
         :ok <- validate_constraints(Map.get(claims, "constraints", :absent)),
         :ok <- validate_trust_marks(Map.get(claims, "trust_marks", :absent)) do
      validate_critical_claims(claims)
    end
  end

  defp validate_metadata(:absent), do: :ok

  defp validate_metadata(metadata) when is_map(metadata) do
    valid? =
      Enum.all?(metadata, fn
        {entity_type, type_metadata} when is_binary(entity_type) and is_map(type_metadata) ->
          Enum.all?(type_metadata, fn {parameter, value} -> is_binary(parameter) and not is_nil(value) end)

        _entry ->
          false
      end)

    if valid?, do: :ok, else: {:error, :invalid_entity_statement}
  end

  defp validate_metadata(_metadata), do: {:error, :invalid_entity_statement}

  defp validate_metadata_policy(:absent), do: :ok

  defp validate_metadata_policy(policy) when is_map(policy) and map_size(policy) > 0 do
    case MetadataPolicy.merge(%{}, policy) do
      {:ok, _normalized} -> :ok
      {:error, :policy_error} -> {:error, :invalid_entity_statement}
    end
  end

  defp validate_metadata_policy(_policy), do: {:error, :invalid_entity_statement}

  defp validate_authority_hints(:absent), do: :ok

  defp validate_authority_hints(hints) when is_list(hints) and hints != [] do
    if Enum.all?(hints, &entity_identifier?/1), do: :ok, else: {:error, :invalid_entity_statement}
  end

  defp validate_authority_hints(_hints), do: {:error, :invalid_entity_statement}

  defp validate_constraints(:absent), do: :ok

  defp validate_constraints(constraints) when is_map(constraints) do
    if Enum.all?(Map.keys(constraints), &is_binary/1), do: :ok, else: {:error, :invalid_entity_statement}
  end

  defp validate_constraints(_constraints), do: {:error, :invalid_entity_statement}

  defp validate_trust_marks(:absent), do: :ok

  defp validate_trust_marks(marks) when is_list(marks) do
    valid? =
      Enum.all?(marks, fn
        %{"trust_mark_type" => type, "trust_mark" => jwt}
        when is_binary(type) and type != "" and is_binary(jwt) and jwt != "" ->
          true

        _mark ->
          false
      end)

    if valid?, do: :ok, else: {:error, :invalid_entity_statement}
  end

  defp validate_trust_marks(_marks), do: {:error, :invalid_entity_statement}

  defp validate_critical_claims(claims) do
    if Map.has_key?(claims, "crit") or Map.has_key?(claims, "metadata_policy_crit"),
      do: {:error, :invalid_entity_statement},
      else: :ok
  end

  defp validate_expected_entity(claims, opts) do
    issuer_ok? = expected_claim?(claims, "iss", Keyword.get(opts, :issuer))
    subject_ok? = expected_claim?(claims, "sub", Keyword.get(opts, :subject))

    if issuer_ok? and subject_ok?, do: :ok, else: {:error, :invalid_entity_statement}
  end

  defp expected_claim?(_claims, _claim, nil), do: true
  defp expected_claim?(claims, claim, expected), do: Map.get(claims, claim) == expected

  defp validate_temporal_claims(claims, opts) do
    now = NumericDate.now(opts, default: :system, invalid_override: :fallback)
    leeway = Keyword.get(opts, :leeway, 0)

    cond do
      not (is_integer(leeway) and leeway >= 0) -> {:error, :invalid_entity_statement}
      not NumericDate.not_before_reached?(claims["iat"], now, skew: leeway) -> {:error, :not_yet_valid}
      not NumericDate.not_expired?(claims["exp"], now, leeway: leeway) -> {:error, :expired}
      true -> :ok
    end
  end

  defp validate_trusted_keys(jwks) do
    case normalize_keys(jwks) do
      [_ | _] = keys -> if valid_key_maps?(keys), do: :ok, else: {:error, :invalid_signature}
      _other -> {:error, :invalid_signature}
    end
  end

  defp valid_embedded_jwks?(%{"keys" => [_ | _] = keys}), do: valid_key_maps?(keys)
  defp valid_embedded_jwks?(_jwks), do: false

  defp valid_key_maps?(keys) do
    kids = Enum.map(keys, &key_kid/1)

    Enum.all?(keys, &valid_public_key_map?/1) and
      Enum.all?(kids, &(is_binary(&1) and &1 != "")) and
      length(kids) == length(Enum.uniq(kids))
  end

  defp valid_public_key_map?(key) when is_map(key) do
    alg = trusted_key_alg(key)

    not Enum.any?(@private_jwk_members, &Map.has_key?(key, &1)) and
      match?({:ok, %JOSE.JWK{}}, Key.verification_jwk(key, alg: alg, minimum_rsa_bits: 1))
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp valid_public_key_map?(_key), do: false

  defp trusted_key_alg(key) do
    Map.get(key, "alg") || key |> JOSE.JWK.from_map() |> SigningAlg.infer()
  end

  defp normalize_keys(%{"keys" => keys}) when is_list(keys), do: keys
  defp normalize_keys(keys) when is_list(keys), do: keys
  defp normalize_keys(%{} = key), do: [key]
  defp normalize_keys(_keys), do: []

  defp key_kid(%{} = key), do: Map.get(key, "kid")
  defp key_kid(_key), do: nil

  defp self_issued?(%{"iss" => entity, "sub" => entity}), do: true
  defp self_issued?(_claims), do: false

  defp entity_identifier?(value) when is_binary(value) and value != "" do
    case URI.parse(value) do
      %URI{scheme: "https", host: host, query: nil, fragment: nil} when is_binary(host) and host != "" -> true
      _other -> false
    end
  end

  defp entity_identifier?(_value), do: false
end
