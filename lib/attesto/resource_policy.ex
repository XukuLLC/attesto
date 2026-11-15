if Code.ensure_loaded?(Plug.Conn) do
  defmodule Attesto.ResourcePolicy do
    @moduledoc false

    # Conn-free validation of resource audience, origin and transport
    # configuration, shared by the resource plugs and their wrappers.
    alias Attesto.Plug.Authenticate, as: AttestoAuthenticate
    alias Attesto.ResourceMetadata, as: Metadata
    alias Attesto.URI, as: AttestoURI

    @doc false
    def validate_htu_opt!(opts) do
      if Keyword.has_key?(opts, :htu) and not is_function(Keyword.get(opts, :htu), 1) do
        raise ArgumentError,
              "Attesto.Plug.ResourceAuthenticate: :htu must be a 1-arity function (conn -> uri); " <>
                "got #{inspect(Keyword.get(opts, :htu))}"
      end
    end

    @doc false
    def validate_dynamic_origin_options!(opts) do
      allow_dynamic = Keyword.get(opts, :allow_dynamic_origin, false)

      if not is_boolean(allow_dynamic) do
        raise ArgumentError, ":allow_dynamic_origin must be a boolean"
      end

      if Keyword.has_key?(opts, :allowed_hosts) and not allow_dynamic do
        raise ArgumentError,
              ":allowed_hosts applies only with allow_dynamic_origin: true; a pinned origin never consults Host"
      end

      if allow_dynamic, do: validate_enabled_dynamic_origin!(opts), else: :ok
    end

    defp validate_enabled_dynamic_origin!(opts) do
      if origin_pinned?(opts) do
        raise ArgumentError, ":allow_dynamic_origin cannot be combined with :base_url or :origin"
      end

      hosts = Keyword.get(opts, :allowed_hosts)

      if is_list(hosts) and hosts != [] and Enum.all?(hosts, &valid_allowed_host?/1) do
        :ok
      else
        raise ArgumentError, ":allowed_hosts must be a non-empty list of host or host:port strings"
      end
    end

    @doc false
    def validate_dpop_pin!(opts) do
      if AttestoAuthenticate.accepts_dpop?(opts) and not Keyword.has_key?(opts, :htu) do
        cond do
          origin_pinned?(opts) ->
            validate_dpop_pinned_scheme!(opts)

          Keyword.get(opts, :allow_dynamic_origin) != true ->
            raise ArgumentError,
                  "Attesto.Plug.ResourceAuthenticate: a mount that accepts DPoP requires :base_url, :origin, :htu, " <>
                    "or allow_dynamic_origin: true with :allowed_hosts"

          true ->
            :ok
        end
      end
    end

    defp validate_dpop_pinned_scheme!(opts) do
      Enum.each([:base_url, :origin], fn key ->
        with {:ok, value} <- Keyword.fetch(opts, key),
             true <- is_binary(value),
             {:ok, %URI{scheme: scheme, host: host}} when is_binary(scheme) <- URI.new(value),
             true <- String.downcase(scheme) == "http",
             false <- is_binary(host) and AttestoURI.loopback_host?(host) do
          raise ArgumentError,
                "Attesto.Plug.ResourceAuthenticate: #{inspect(key)} must be HTTPS or loopback HTTP when DPoP is enabled"
        end
      end)
    end

    defp valid_allowed_host?(host) when is_binary(host) do
      byte_size(host) in 1..255 and String.valid?(host) and
        not String.contains?(host, [" ", "\t", "\r", "\n", "/", "\\", "@", "?", "#"])
    end

    defp valid_allowed_host?(_host), do: false

    @doc false
    def validate_audience_policy!(opts) do
      resource_audience = Keyword.get(opts, :resource_audience)
      validate_explicit_audience_policy!(resource_audience, Keyword.fetch(opts, :trusted_audiences))

      if resource_audience == :resource and not is_binary(Keyword.get(opts, :resource_path)) do
        raise ArgumentError,
              "resource_audience: :resource requires a :resource / :resource_path option to derive the audience"
      end

      if resource_audience == :resource do
        Metadata.require_pinned_origin!(opts)
        validate_audience_origin!(opts)
      end

      if !valid_resource_audience_policy?(resource_audience) do
        raise ArgumentError,
              ":resource_audience must be :resource, a non-empty identifier, a one-arity function, or an MFA tuple"
      end

      :ok
    end

    defp validate_audience_origin!(opts) do
      Enum.each([:base_url, :origin], fn key ->
        validate_audience_pin!(Keyword.get(opts, key), Keyword.get(opts, :allow_http, false))
      end)
    end

    defp validate_audience_pin!(value, allow_http?) when is_binary(value) do
      if !Metadata.resource_url?(value, allow_http?),
        do: raise(ArgumentError, "resource audience pins require HTTPS or loopback HTTP under allow_http: true")
    end

    defp validate_audience_pin!(_callback, _allow_http?), do: :ok

    defp validate_explicit_audience_policy!(resource_audience, :error) when resource_audience in [nil, false] do
      raise ArgumentError,
            "configure :resource_audience or :trusted_audiences explicitly; " <>
              "metadata and config.audience alone do not select a resource audience policy"
    end

    defp validate_explicit_audience_policy!(resource_audience, {:ok, _trusted})
         when resource_audience not in [nil, false] do
      raise ArgumentError,
            ":resource_audience and :trusted_audiences are mutually exclusive; choose one audience policy"
    end

    defp validate_explicit_audience_policy!(_resource_audience, {:ok, trusted}) do
      if not valid_trusted_audiences_policy?(trusted) do
        raise ArgumentError,
              ":trusted_audiences must be a non-empty list of non-empty identifiers or a one-arity function"
      end

      :ok
    end

    defp validate_explicit_audience_policy!(_resource_audience, :error), do: :ok

    defp valid_resource_audience_policy?(value) when value in [nil, false, :resource], do: true
    defp valid_resource_audience_policy?(value) when is_binary(value), do: value != ""
    defp valid_resource_audience_policy?(value) when is_function(value, 1), do: true

    defp valid_resource_audience_policy?({module, fun}) when is_atom(module) and is_atom(fun), do: true

    defp valid_resource_audience_policy?({module, fun, args}) when is_atom(module) and is_atom(fun) and is_list(args),
      do: true

    defp valid_resource_audience_policy?(_value), do: false

    # Core verifies the resolved policy and token together at request time. Check
    # the static option here so a missing or malformed decision fails at boot.
    defp valid_trusted_audiences_policy?([_ | _] = audiences), do: Enum.all?(audiences, &(is_binary(&1) and &1 != ""))

    defp valid_trusted_audiences_policy?(resolver), do: is_function(resolver, 1)

    @doc false
    def validate_resource_path!(opts) do
      case Keyword.fetch(opts, :resource_path) do
        {:ok, resource_path} ->
          _ = Metadata.normalize_resource_path!(resource_path)
          :ok

        :error ->
          :ok
      end
    end

    @doc false
    def validate_resource_metadata_url!(opts) do
      case Keyword.fetch(opts, :resource_metadata_url) do
        :error ->
          :ok

        {:ok, spec} ->
          validate_resource_metadata_url_spec!(spec, opts)
      end
    end

    defp validate_resource_metadata_url_spec!(url, opts) when is_binary(url) do
      case valid_resource_metadata_url(url, Keyword.get(opts, :allow_http, false)) do
        {:ok, _url} -> :ok
        :error -> raise_invalid_resource_metadata_url!()
      end
    end

    defp validate_resource_metadata_url_spec!(fun, _opts) when is_function(fun, 1), do: :ok

    defp validate_resource_metadata_url_spec!({module, fun}, _opts) when is_atom(module) and is_atom(fun), do: :ok

    defp validate_resource_metadata_url_spec!({module, fun, args}, _opts)
         when is_atom(module) and is_atom(fun) and is_list(args), do: :ok

    defp validate_resource_metadata_url_spec!(_invalid, _opts), do: raise_invalid_resource_metadata_url!()

    defp origin_pinned?(opts), do: Enum.any?([:base_url, :origin], &Keyword.has_key?(opts, &1))

    defp valid_resource_metadata_url(url, allow_http?) do
      if Metadata.resource_url?(url, allow_http?), do: {:ok, url}, else: :error
    end

    defp raise_invalid_resource_metadata_url! do
      raise ArgumentError,
            ":resource_metadata_url must be an absolute HTTPS URL without userinfo or fragment; " <>
              "set allow_http: true only for a deliberate development endpoint"
    end
  end
end
