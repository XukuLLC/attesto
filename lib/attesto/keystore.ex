defmodule Attesto.Keystore do
  @moduledoc """
  The behaviour Attesto uses to obtain signing and verification keys.

  A keystore answers two questions:

    * **What key do we sign new tokens with?** `signing_pem/0` returns the
      private signing key PEM. Attesto derives the public half and the `kid`
      from it (`Attesto.Key`), so the keystore never has to compute a
      thumbprint.

    * **What keys may verify a presented token?** `verification_pems/0`
      returns a list of PEMs (private or public) whose public halves are
      trusted. With a single key this is just `[signing_pem()]`. During a
      key rotation it carries both the outgoing and incoming keys so
      tokens minted under either verify, and `Attesto.Token.verify/3`
      selects the right one by the JWS header `kid`.

  Implementations decide *where* keys come from - an environment variable, a
  secrets manager, or a file. The legacy signing path consumes a private PEM.
  A module backed by an HSM, KMS, enclave, or other non-extractable custody
  system instead implements `Attesto.Signer` alongside this behaviour and may
  omit `signing_pem/0`; its `verification_pems/0` still publishes public keys.

  A FAPI deployment that uses RSA must provision every server signing and
  verification key with a modulus of at least 2048 bits. The generic keystore
  contract remains profile-neutral so non-FAPI applications can make their
  own compatibility decisions.

  `Attesto.Keystore.Static` is a ready-made implementation for the common
  single-key (or manually-rotated) case.
  """

  alias Attesto.{Key, Signer, SigningAlg, Thumbprint}

  @type key_metadata :: %{optional(:not_after) => DateTime.t() | non_neg_integer()}

  @type rotation_key :: %{
          kid: String.t(),
          alg: String.t(),
          current?: boolean(),
          not_after: DateTime.t() | nil,
          state: :current | :overlap | :expiring | :expired
        }

  @type rotation_health :: %{
          status: :healthy | :warning | :invalid,
          signing_kid: String.t(),
          overlap?: boolean(),
          key_count: non_neg_integer(),
          keys: [rotation_key()],
          unknown_metadata_kids: [String.t()],
          issues: [atom()]
        }

  @doc """
  The private signing-key PEM used to sign newly issued tokens.

  The key must support one of the asymmetric algorithms accepted by
  `Attesto.SigningAlg`. FAPI server deployments using RSA require a modulus of
  at least 2048 bits.
  """
  @callback signing_pem() :: String.t()

  @doc """
  The PEMs (private or public) whose public halves are trusted to verify
  a presented token. MUST include the public half of whatever
  `signing_pem/0` currently returns.
  """
  @callback verification_pems() :: [String.t()]

  @doc """
  Optional per-key JOSE algorithm metadata, keyed by RFC 7638 `kid`.

  When omitted, Attesto infers an algorithm from the public key type and curve:
  RSA -> RS256, P-256 -> ES256, P-384 -> ES384, P-521 -> ES512, and
  Ed25519/Ed448 -> legacy EdDSA. Use this callback to label RSA keys that
  should verify as PS256, select RFC 9864 `Ed25519` / `Ed448` for the matching
  curve, or make a rotation window explicit. Ed448 deployments must configure
  JOSE with Curve448 and SHAKE256 support.
  """
  @callback key_algs() :: %{String.t() => String.t()} | keyword(String.t())

  @doc """
  Optional global algorithm for the current signing key.

  This is a convenience for single-key RSA deployments that want PS256
  without precomputing the signing key's `kid`. A custom keystore whose value
  differs from key inference MUST expose the same binding through `key_algs/0`
  so its newly minted tokens also verify. `Attesto.Keystore.Static` does that
  automatically. Verification otherwise uses `key_algs/0` when present, then
  key inference.
  """
  @callback signing_alg() :: String.t()

  @doc """
  Optional operator metadata for verification keys, keyed by RFC 7638 `kid`.

  `:not_after` is either a UTC `DateTime` or a Unix timestamp. It is operational
  metadata: JWT verification continues to use token validity and the published
  key set, while `rotation_health/2` surfaces expired or soon-to-expire keys.
  Keys must be non-empty string `kid` values that exist in
  `verification_pems/0`; malformed and unknown metadata fails closed.
  """
  @callback verification_key_metadata() :: %{optional(String.t()) => key_metadata()}

  @doc """
  Inspect a keystore's rotation contract.

  The current signing key must appear in `verification_pems/0`; otherwise newly
  issued tokens cannot be verified and the result is `:invalid`. More than one
  verification key is reported as an active overlap window. Optional
  `verification_key_metadata/0` expiry values turn expired and soon-to-expire
  keys into explicit health issues. An expired current signing key and metadata
  for an unknown key make the result `:invalid`; expired overlap keys warn.

  Options:

    * `:now` - UTC `DateTime` or Unix timestamp; defaults to the current time.
    * `:expiry_warning_seconds` - warning horizon; defaults to seven days.
  """
  @spec rotation_health(module(), keyword()) :: rotation_health()
  def rotation_health(keystore, opts \\ []) when is_atom(keystore) and is_list(opts) do
    validate!(keystore)
    now = opts |> Keyword.get(:now, DateTime.utc_now()) |> normalize_datetime!(:now)
    warning_seconds = Keyword.get(opts, :expiry_warning_seconds, 7 * 24 * 60 * 60)
    validate_warning_seconds!(warning_seconds)

    signing_jwk = current_signing_jwk(keystore)
    {:ok, signing_kid} = Thumbprint.of_jwk(signing_jwk)
    verification_pems = verification_pems!(keystore)
    verification_kids = Enum.map(verification_pems, &Key.kid/1)
    metadata = verification_metadata(keystore)
    unknown_metadata_kids = validate_metadata!(metadata, verification_kids)

    keys =
      verification_pems
      |> Enum.map(&rotation_key(keystore, &1, signing_kid, metadata, now, warning_seconds))
      |> Enum.uniq_by(& &1.kid)

    issues = rotation_issues(keys, signing_kid, unknown_metadata_kids)

    %{
      status: rotation_status(issues),
      signing_kid: signing_kid,
      overlap?: length(keys) > 1,
      key_count: length(keys),
      keys: keys,
      unknown_metadata_kids: unknown_metadata_kids,
      issues: issues
    }
  end

  @doc false
  @spec validate!(module()) :: :ok
  def validate!(keystore) when is_atom(keystore) and not is_nil(keystore) do
    ensure_loaded!(keystore)
    require_callback!(keystore, :verification_pems, 0)

    signing_jwk? = function_exported?(keystore, :signing_jwk, 0)
    sign? = function_exported?(keystore, :sign, 2)

    cond do
      signing_jwk? != sign? ->
        raise ArgumentError,
              "#{inspect(keystore)} must export both signing_jwk/0 and sign/2 for external signing"

      signing_jwk? and sign? ->
        :ok

      function_exported?(keystore, :signing_pem, 0) ->
        :ok

      true ->
        raise ArgumentError,
              "#{inspect(keystore)} must export signing_pem/0 or both signing_jwk/0 and sign/2"
    end
  end

  def validate!(other) do
    raise ArgumentError, "keystore must be a module; got #{inspect(other)}"
  end

  defp current_signing_jwk(keystore) do
    if Signer.external?(keystore) do
      Signer.signing_jwk!(keystore)
    else
      keystore.signing_pem() |> Key.signing_jwk()
    end
  end

  defp verification_pems!(keystore) do
    case keystore.verification_pems() do
      pems when is_list(pems) ->
        if Enum.all?(pems, &(is_binary(&1) and byte_size(&1) > 0)) do
          pems
        else
          raise ArgumentError,
                "#{inspect(keystore)}.verification_pems/0 must return only non-empty PEM binaries"
        end

      other ->
        raise ArgumentError,
              "#{inspect(keystore)}.verification_pems/0 must return a list; got #{inspect(other)}"
    end
  end

  defp verification_metadata(keystore) do
    if function_exported?(keystore, :verification_key_metadata, 0) do
      case keystore.verification_key_metadata() do
        metadata when is_map(metadata) -> metadata
        other -> raise ArgumentError, "verification_key_metadata/0 must return a map; got #{inspect(other)}"
      end
    else
      %{}
    end
  end

  defp validate_metadata!(metadata, verification_kids) do
    metadata
    |> Enum.map(fn
      {kid, value} when is_binary(kid) and kid != "" ->
        _ = metadata_not_after!(value, kid)
        kid

      {kid, _value} ->
        raise ArgumentError,
              "verification_key_metadata/0 keys must be non-empty RFC 7638 kid strings; got #{inspect(kid)}"
    end)
    |> Enum.reject(&(&1 in verification_kids))
    |> Enum.sort()
  end

  defp rotation_key(keystore, pem, signing_kid, metadata, now, warning_seconds) do
    kid = Key.kid(pem)
    not_after = metadata |> Map.get(kid, %{}) |> metadata_not_after!(kid)
    current? = kid == signing_kid

    %{
      kid: kid,
      alg: SigningAlg.for_key(keystore, pem),
      current?: current?,
      not_after: not_after,
      state: key_state(current?, not_after, now, warning_seconds)
    }
  end

  defp metadata_not_after!(metadata, _kid) when metadata == %{}, do: nil

  defp metadata_not_after!(metadata, kid) when is_struct(metadata) do
    raise ArgumentError, "verification key metadata for #{kid} must be a map; got #{inspect(metadata)}"
  end

  defp metadata_not_after!(metadata, kid) when is_map(metadata) do
    keys = Map.keys(metadata)
    unknown_keys = keys -- [:not_after, "not_after"]

    cond do
      unknown_keys != [] ->
        raise ArgumentError,
              "verification key metadata for #{kid} has unsupported keys #{inspect(unknown_keys)}"

      :not_after in keys and "not_after" in keys ->
        raise ArgumentError,
              "verification key metadata for #{kid} must not contain both :not_after and \"not_after\""

      true ->
        case Map.get(metadata, :not_after, Map.get(metadata, "not_after")) do
          nil -> nil
          value -> normalize_datetime!(value, "verification key #{kid} :not_after")
        end
    end
  end

  defp metadata_not_after!(other, kid) do
    raise ArgumentError, "verification key metadata for #{kid} must be a map; got #{inspect(other)}"
  end

  defp key_state(current?, %DateTime{} = not_after, now, warning_seconds) do
    cond do
      DateTime.compare(not_after, now) != :gt -> :expired
      DateTime.diff(not_after, now, :second) <= warning_seconds -> :expiring
      current? -> :current
      true -> :overlap
    end
  end

  defp key_state(true, nil, _now, _warning_seconds), do: :current
  defp key_state(false, nil, _now, _warning_seconds), do: :overlap

  defp rotation_issues(keys, signing_kid, unknown_metadata_kids) do
    []
    |> maybe_issue(keys == [], :empty_verification_set)
    |> maybe_issue(not Enum.any?(keys, &(&1.kid == signing_kid)), :signing_key_not_published)
    |> maybe_issue(Enum.any?(keys, &(&1.current? and &1.state == :expired)), :expired_signing_key)
    |> maybe_issue(Enum.any?(keys, &(&1.current? and &1.state == :expiring)), :expiring_signing_key)
    |> maybe_issue(Enum.any?(keys, &(not &1.current? and &1.state == :expired)), :expired_verification_key)
    |> maybe_issue(Enum.any?(keys, &(not &1.current? and &1.state == :expiring)), :expiring_verification_key)
    |> maybe_issue(unknown_metadata_kids != [], :unknown_verification_key_metadata)
  end

  defp maybe_issue(issues, true, issue), do: issues ++ [issue]
  defp maybe_issue(issues, false, _issue), do: issues

  defp rotation_status(issues) do
    cond do
      :empty_verification_set in issues -> :invalid
      :signing_key_not_published in issues -> :invalid
      :expired_signing_key in issues -> :invalid
      :unknown_verification_key_metadata in issues -> :invalid
      issues == [] -> :healthy
      true -> :warning
    end
  end

  defp normalize_datetime!(%DateTime{} = value, _field), do: DateTime.truncate(value, :second)

  defp normalize_datetime!(value, _field) when is_integer(value) and value >= 0 do
    case DateTime.from_unix(value) do
      {:ok, datetime} -> datetime
      {:error, reason} -> raise ArgumentError, "invalid Unix timestamp #{inspect(value)}: #{inspect(reason)}"
    end
  end

  defp normalize_datetime!(value, field) do
    raise ArgumentError, "#{field} must be a UTC DateTime or Unix timestamp; got #{inspect(value)}"
  end

  defp validate_warning_seconds!(value) when is_integer(value) and value >= 0, do: :ok

  defp validate_warning_seconds!(value) do
    raise ArgumentError, ":expiry_warning_seconds must be a non-negative integer; got #{inspect(value)}"
  end

  defp ensure_loaded!(module) do
    case Code.ensure_loaded(module) do
      {:module, ^module} -> :ok
      {:error, reason} -> raise ArgumentError, "could not load keystore #{inspect(module)}: #{inspect(reason)}"
    end
  end

  defp require_callback!(module, function, arity) do
    if function_exported?(module, function, arity) do
      :ok
    else
      raise ArgumentError, "#{inspect(module)} must export #{function}/#{arity}"
    end
  end

  @optional_callbacks signing_pem: 0, key_algs: 0, signing_alg: 0, verification_key_metadata: 0
end
