defmodule Attesto.Keystore.Static do
  @moduledoc """
  A simple `Attesto.Keystore` backed by application configuration.

  Reads its signing material from the `:attesto` application environment:

      config :attesto, Attesto.Keystore.Static,
        signing_pem: System.fetch_env!("OAUTH_SIGNING_PRIVATE_KEY_PEM"),
        # optional; defaults to [signing_pem] when omitted
        verification_pems: [current_pem, previous_pem],
        # optional; RSA defaults to RS256, EC/OKP infer from curve
        signing_alg: "PS256",
        key_algs: %{current_kid => "PS256", previous_kid => "RS256"}

  Only `signing_pem` is required. When `verification_pems` is omitted, the
  verification set is exactly the signing key, which is the correct
  single-key default - and because Attesto derives the public half from
  the private key, the signing and verifying keys can never drift.

  During a rotation, set `verification_pems` to both the new and old keys
  while `signing_pem` points at the new one; once no live tokens were
  minted under the old key, drop it from the list.

  Hosts with their own resolution (a secrets manager, a fail-fast boot
  check, an HSM) implement `Attesto.Keystore` directly instead of using
  this module.
  """

  @behaviour Attesto.Keystore

  @impl true
  def signing_pem do
    case fetch(:signing_pem) do
      pem when is_binary(pem) and pem != "" ->
        pem

      "" ->
        raise ArgumentError, """
        #{inspect(__MODULE__)} :signing_pem is set but empty.

        An empty signing key usually means the env var it was read from is
        unset and resolved to "". Provision the PEM contents, e.g.

            config :attesto, #{inspect(__MODULE__)},
              signing_pem: System.fetch_env!("OAUTH_SIGNING_PRIVATE_KEY_PEM")
        """

      _ ->
        raise ArgumentError, """
        #{inspect(__MODULE__)} has no :signing_pem configured.

        Set it under the :attesto application environment, e.g.

            config :attesto, #{inspect(__MODULE__)},
              signing_pem: System.fetch_env!("OAUTH_SIGNING_PRIVATE_KEY_PEM")
        """
    end
  end

  @impl true
  def verification_pems do
    case fetch(:verification_pems) do
      # Omitted or an explicit empty list: default to the signing key (the
      # single-key, no-rotation posture). An empty verification set would
      # verify nothing, so defaulting is the safe interpretation.
      nil ->
        [signing_pem()]

      [] ->
        [signing_pem()]

      pems when is_list(pems) ->
        validate_pems!(pems)

      # A present-but-non-list value (e.g. a stray `verification_pems: ""`)
      # is a typo, not a default. Fail loudly so a rotation
      # misconfiguration surfaces at boot instead of silently collapsing to
      # the signing key.
      other ->
        raise ArgumentError, """
        #{inspect(__MODULE__)} :verification_pems must be a list of PEM strings \
        (or omitted to default to the signing key); got #{inspect(other)}.
        """
    end
  end

  @impl true
  def signing_alg do
    case fetch(:signing_alg) do
      nil -> Attesto.SigningAlg.infer(Attesto.Key.signing_jwk(signing_pem()))
      alg when is_binary(alg) -> Attesto.SigningAlg.validate!(alg)
      other -> raise ArgumentError, "#{inspect(__MODULE__)} :signing_alg must be a string; got #{inspect(other)}."
    end
  end

  @impl true
  def key_algs do
    configured =
      case fetch(:key_algs) do
        nil ->
          %{}

        algs when is_map(algs) or is_list(algs) ->
          Map.new(algs)

        other ->
          raise ArgumentError, "#{inspect(__MODULE__)} :key_algs must be a map or keyword/list; got #{inspect(other)}."
      end

    # When :signing_alg is set explicitly, label the signing key's own kid with
    # it so verification agrees with signing. Otherwise verification infers the
    # alg from the key type (e.g. RS256 for an RSA key configured to sign PS256)
    # and rejects the server's own tokens as :invalid_signature. An explicit
    # :key_algs entry for that kid still wins.
    case fetch(:signing_alg) do
      alg when is_binary(alg) ->
        Map.put_new(configured, Attesto.Key.kid(signing_pem()), Attesto.SigningAlg.validate!(alg))

      _ ->
        configured
    end
  end

  defp validate_pems!(pems) do
    Enum.each(pems, fn
      pem when is_binary(pem) and pem != "" ->
        :ok

      bad ->
        raise ArgumentError, """
        #{inspect(__MODULE__)} :verification_pems entries must each be a non-empty \
        PEM string; got #{inspect(bad)} in the list.
        """
    end)

    pems
  end

  defp fetch(key) do
    :attesto
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(key)
  end
end
