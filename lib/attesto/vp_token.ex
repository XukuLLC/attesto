defmodule Attesto.VpToken do
  @moduledoc """
  OID4VP `vp_token` verification for SD-JWT VCs (OID4VP §7).

  The response is a DCQL-shaped map from credential-query IDs to one or more
  SD-JWT VC presentations. Verification is conn-free and delegates issuer
  signature, disclosure, VC claim, and holder Key Binding JWT checks to the
  existing `Attesto.SdJwtVc` and `Attesto.SdJwt` engines.

  Holder key binding is mandatory here: a credential without a `cnf.jwk` or a
  valid Key Binding JWT cannot satisfy an OID4VP request.
  """

  alias Attesto.{JWS, SdJwt, SdJwtVc}

  @separator "~"

  @type safe_result :: %{
          vct: String.t(),
          iss: String.t(),
          claims: map(),
          cnf: map() | nil
        }

  @type verify_result :: {:ok, map()} | {:error, term()}

  @doc """
  Verify an OID4VP `vp_token` carrying SD-JWT VC presentations.

  Required options are `:nonce`, `:audience`, and exactly one issuer trust
  source: `:issuer_jwks` for static issuer keys or `:resolve_issuer` for a
  callback receiving the issuer's `iss` claim. The optional `:now` value is
  passed to both the VC and holder-binding verifiers.

  A string presentation produces one safe result for its query ID. A list of
  presentations produces a list of safe results. Raw JWTs are never returned.
  """
  @spec verify(term(), keyword()) :: verify_result()
  def verify(vp_token, opts \\ []) do
    validate_vp_token!(vp_token)
    opts = ensure_keyword!(opts)
    nonce = required_option!(opts, :nonce)
    audience = required_option!(opts, :audience)
    issuer_source = issuer_source!(opts)
    expected_query_ids = expected_query_ids!(opts)
    validate_presentations!(vp_token)

    case missing_query_ids(vp_token, expected_query_ids) do
      [] -> verify_presentations(vp_token, issuer_source, nonce, audience, opts)
      missing_ids -> {:error, {:missing_credentials, missing_ids}}
    end
  end

  defp verify_presentations(vp_token, issuer_source, nonce, audience, opts) do
    verify_opts = now_opts(opts)
    binding_opts = [nonce: nonce, audience: audience] ++ verify_opts

    Enum.reduce_while(vp_token, {:ok, %{}}, fn {id, presentation}, {:ok, results} ->
      case verify_value(presentation, issuer_source, verify_opts, binding_opts) do
        {:ok, result} -> {:cont, {:ok, Map.put(results, id, result)}}
        {:error, reason} -> {:halt, {:error, {id, reason}}}
      end
    end)
  end

  defp verify_value(presentation, issuer_source, verify_opts, binding_opts)

  defp verify_value(presentation, issuer_source, verify_opts, binding_opts) when is_binary(presentation) do
    with {:ok, verified} <- verify_one(presentation, issuer_source, verify_opts, binding_opts) do
      {:ok, safe_result(verified)}
    end
  end

  defp verify_value(presentations, issuer_source, verify_opts, binding_opts) when is_list(presentations) do
    presentations
    |> Enum.reduce_while({:ok, []}, fn presentation, {:ok, results} ->
      case verify_one(presentation, issuer_source, verify_opts, binding_opts) do
        {:ok, verified} -> {:cont, {:ok, [safe_result(verified) | results]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> reverse_list_result()
  end

  defp verify_one(presentation, {:static, jwks}, verify_opts, binding_opts) do
    with {:ok, verified} <- SdJwtVc.verify(presentation, jwks, verify_opts),
         :ok <- verify_holder_binding(verified, binding_opts) do
      {:ok, verified}
    end
  end

  defp verify_one(presentation, {:resolver, resolver}, verify_opts, binding_opts) do
    with {:ok, jwks} <- resolve_issuer_jwks(presentation, resolver),
         {:ok, verified} <- SdJwtVc.verify(presentation, jwks, verify_opts),
         :ok <- verify_holder_binding(verified, binding_opts) do
      {:ok, verified}
    end
  end

  defp verify_holder_binding(%{cnf: %{"jwk" => holder_jwk}} = verified, binding_opts) when is_map(holder_jwk) do
    SdJwt.verify_key_binding(verified, holder_jwk, binding_opts)
  end

  defp verify_holder_binding(_verified, _binding_opts), do: {:error, :missing_holder_key}

  defp resolve_issuer_jwks(presentation, resolver) do
    with {:ok, issuer_jwt} <- issuer_jwt(presentation),
         {:ok, payload} <- JWS.peek_json(issuer_jwt, :payload),
         {:ok, iss} <- issuer(payload) do
      case resolver.(iss) do
        {:ok, jwks} -> {:ok, jwks}
        {:error, reason} -> {:error, {:issuer, reason}}
        other -> {:error, {:issuer, {:invalid_resolver_result, other}}}
      end
    end
  end

  defp issuer_jwt(presentation) do
    case :binary.split(presentation, @separator) do
      [issuer_jwt, _rest] when issuer_jwt != "" -> {:ok, issuer_jwt}
      _ -> {:error, :malformed}
    end
  end

  defp issuer(%{"iss" => iss}) when is_binary(iss) and iss != "", do: {:ok, iss}
  defp issuer(_payload), do: {:error, :missing_iss}

  defp safe_result(verified) do
    %{
      vct: verified.vct,
      iss: verified.iss,
      claims: verified.claims,
      cnf: verified.cnf
    }
  end

  defp reverse_list_result({:ok, results}), do: {:ok, Enum.reverse(results)}
  defp reverse_list_result({:error, _reason} = error), do: error

  defp validate_vp_token!(vp_token) when is_map(vp_token), do: :ok

  defp validate_vp_token!(vp_token) do
    raise ArgumentError,
          "Attesto.VpToken.verify/2 expects a map; got #{inspect(vp_token)}"
  end

  defp ensure_keyword!(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      opts
    else
      raise ArgumentError,
            "Attesto.VpToken.verify/2 expects options as a keyword list; got #{inspect(opts)}"
    end
  end

  defp ensure_keyword!(opts) do
    raise ArgumentError,
          "Attesto.VpToken.verify/2 expects options as a keyword list; got #{inspect(opts)}"
  end

  defp required_option!(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> value
      :error -> raise ArgumentError, "Attesto.VpToken.verify/2 requires :#{key}"
    end
  end

  defp issuer_source!(opts) do
    has_static = Keyword.has_key?(opts, :issuer_jwks)
    has_resolver = Keyword.has_key?(opts, :resolve_issuer)

    case {has_static, has_resolver} do
      {true, true} ->
        raise ArgumentError,
              "Attesto.VpToken.verify/2 accepts exactly one of :issuer_jwks or :resolve_issuer"

      {false, false} ->
        raise ArgumentError,
              "Attesto.VpToken.verify/2 requires :issuer_jwks or :resolve_issuer"

      {true, false} ->
        jwks = Keyword.fetch!(opts, :issuer_jwks)

        if is_map(jwks) or is_list(jwks) do
          {:static, jwks}
        else
          raise ArgumentError,
                "Attesto.VpToken :issuer_jwks must be a JWK map or list; got #{inspect(jwks)}"
        end

      {false, true} ->
        resolver = Keyword.fetch!(opts, :resolve_issuer)

        if is_function(resolver, 1) do
          {:resolver, resolver}
        else
          raise ArgumentError,
                "Attesto.VpToken :resolve_issuer must be a unary function; got #{inspect(resolver)}"
        end
    end
  end

  defp expected_query_ids!(opts) do
    case Keyword.fetch(opts, :expected_query_ids) do
      :error ->
        []

      {:ok, ids} when is_list(ids) ->
        if Enum.all?(ids, &(is_binary(&1) and &1 != "")) do
          ids
        else
          raise ArgumentError,
                "Attesto.VpToken :expected_query_ids must be a list of non-empty strings; got #{inspect(ids)}"
        end

      {:ok, ids} ->
        raise ArgumentError,
              "Attesto.VpToken :expected_query_ids must be a list of non-empty strings; got #{inspect(ids)}"
    end
  end

  defp validate_presentations!(vp_token) do
    Enum.each(vp_token, fn {_id, presentation} -> validate_presentation!(presentation) end)
  end

  defp validate_presentation!(presentation) when is_binary(presentation) and presentation != "", do: :ok

  defp validate_presentation!(presentations) when is_list(presentations) and presentations != [] do
    if Enum.all?(presentations, &(is_binary(&1) and &1 != "")) do
      :ok
    else
      invalid_presentation!(presentations)
    end
  end

  defp validate_presentation!(presentation), do: invalid_presentation!(presentation)

  defp invalid_presentation!(presentation) do
    raise ArgumentError,
          "Attesto.VpToken presentation must be a non-empty binary or list of non-empty binaries; " <>
            "got #{inspect(presentation)}"
  end

  defp missing_query_ids(_vp_token, []), do: []

  defp missing_query_ids(vp_token, expected_query_ids) do
    Enum.reject(expected_query_ids, &Map.has_key?(vp_token, &1))
  end

  defp now_opts(opts) do
    case Keyword.fetch(opts, :now) do
      {:ok, now} -> [now: now]
      :error -> []
    end
  end
end
