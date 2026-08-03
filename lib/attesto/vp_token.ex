defmodule Attesto.VpToken do
  @moduledoc """
  OID4VP `vp_token` verification for SD-JWT VC (`dc+sd-jwt`) and ISO mdoc
  (`mso_mdoc`) presentations (OID4VP §7).

  The response is a DCQL-shaped map from credential-query IDs to one or more
  presentations. Verification is conn-free. SD-JWT VC entries delegate issuer
  signature, disclosure, VC claim, and holder Key Binding JWT checks to
  `Attesto.SdJwtVc` and `Attesto.SdJwt`; `mso_mdoc` entries delegate `Device`-
  `Response` and device-signature checks to `Attesto.Mdoc.verify_device_response/4`.

  Holder key binding is mandatory for SD-JWT VC: a credential without a
  `cnf.jwk` or a valid Key Binding JWT cannot satisfy an OID4VP request. mdoc
  presentations carry their own device-signature binding instead.

  ## Format dispatch

  Each query ID's format is resolved via the optional `:formats` option — a
  map of query ID to `"dc+sd-jwt"` or `"mso_mdoc"` — falling back to shape
  detection when a query ID is absent from `:formats` (or the option itself is
  omitted): a `~`-delimited string is SD-JWT VC, a plain base64url string is
  `mso_mdoc`. Prefer `:formats` when the DCQL query is known ahead of time;
  detection exists for callers that don't thread it through.

  ## mdoc context

  An `mso_mdoc` entry additionally needs `:response_uri` — the OID4VP
  `response_uri` the wallet's `DeviceResponse` was bound to via its
  `OpenID4VPHandover` `SessionTranscript`. `:audience` doubles as the
  handover's `client_id` and the shared `:nonce` as its nonce. Only
  unencrypted `direct_post` is supported (the handover's JWK thumbprint is
  always `nil`). SD-JWT-VC-only callers never need `:response_uri`; it is
  required only when the `vp_token` actually contains an `mso_mdoc` entry.
  """

  alias Attesto.{JWS, MapParams, Mdoc, SdJwt, SdJwtVc}

  @separator "~"
  @base64url ~r/\A[A-Za-z0-9_-]+\z/
  @known_formats %{"dc+sd-jwt" => :sd_jwt_vc, "mso_mdoc" => :mso_mdoc}

  @type safe_result :: %{
          vct: String.t(),
          iss: String.t(),
          claims: map(),
          cnf: map() | nil
        }

  @type mdoc_safe_result :: %{
          doc_type: String.t(),
          namespaces: map(),
          device_namespaces: map(),
          validity: map()
        }

  @type verify_result :: {:ok, map()} | {:error, term()}

  @doc """
  Verify an OID4VP `vp_token` carrying SD-JWT VC and/or `mso_mdoc` presentations.

  Required options are `:nonce`, `:audience`, and exactly one issuer trust
  source: `:issuer_jwks` for static issuer keys or `:resolve_issuer` for a
  callback receiving the presentation's (unverified) issuer identity. The
  optional `:now` value is passed to both the VC/mdoc and holder-binding
  verifiers. See the moduledoc for `:formats` and `:response_uri`.

  > #### `:resolve_issuer` receives UNVERIFIED issuer material {: .warning}
  >
  > For SD-JWT VC, the callback is handed the `iss` peeked from the still-
  > unverified issuer JWT (verifying the signature requires the key, which
  > requires `iss` — so the lookup is unavoidably ahead of verification). For
  > `mso_mdoc`, it is handed the `docType` peeked from the still-unverified
  > `DeviceResponse` in the same way. The signature is then checked against
  > whatever keys the callback returns, so forged issuer material cannot forge
  > a credential — it only misdirects the key lookup. But the callback MUST
  > NOT make a network request derived from this value without an allow-list:
  > the presenter controls it, so a naive fetch is an SSRF sink. Resolve from
  > a trusted issuer registry, not by dereferencing the peeked value.

  A string presentation produces one safe result for its query ID. A list of
  presentations produces a list of safe results. Raw JWTs and raw
  `DeviceResponse` bytes are never returned.
  """
  @spec verify(term(), keyword()) :: verify_result()
  def verify(vp_token, opts \\ []) do
    validate_vp_token!(vp_token)
    opts = MapParams.ensure_keyword!(opts)
    nonce = required_option!(opts, :nonce)
    audience = required_option!(opts, :audience)
    issuer_source = issuer_source!(opts)
    expected_query_ids = expected_query_ids!(opts)
    formats = formats!(opts)
    validate_presentations!(vp_token)

    case missing_query_ids(vp_token, expected_query_ids) do
      [] -> verify_presentations(vp_token, issuer_source, nonce, audience, formats, opts)
      missing_ids -> {:error, {:missing_credentials, missing_ids}}
    end
  end

  defp verify_presentations(vp_token, issuer_source, nonce, audience, formats, opts) do
    verify_opts = now_opts(opts)
    binding_opts = [nonce: nonce, audience: audience] ++ verify_opts
    mdoc_context_result = mdoc_context(nonce, audience, opts)

    Enum.reduce_while(vp_token, {:ok, %{}}, fn {id, presentation}, {:ok, results} ->
      case verify_entry(id, presentation, formats, issuer_source, verify_opts, binding_opts, mdoc_context_result) do
        {:ok, result} -> {:cont, {:ok, Map.put(results, id, result)}}
        {:error, reason} -> {:halt, {:error, {id, reason}}}
      end
    end)
  end

  defp verify_entry(id, presentation, formats, issuer_source, verify_opts, binding_opts, mdoc_context_result) do
    with {:ok, format} <- entry_format(id, presentation, formats) do
      case format do
        :sd_jwt_vc -> verify_value(presentation, issuer_source, verify_opts, binding_opts)
        :mso_mdoc -> verify_mdoc_entry(presentation, issuer_source, verify_opts, mdoc_context_result)
      end
    end
  end

  defp verify_mdoc_entry(_presentation, _issuer_source, _verify_opts, {:error, reason}), do: {:error, reason}

  defp verify_mdoc_entry(presentation, issuer_source, verify_opts, {:ok, mdoc_context}) do
    verify_mdoc_value(presentation, issuer_source, mdoc_context, verify_opts)
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

  # ── mso_mdoc ─────────────────────────────────────────────────────────────

  defp verify_mdoc_value(presentation, issuer_source, mdoc_context, verify_opts) when is_binary(presentation) do
    verify_mdoc_one(presentation, issuer_source, mdoc_context, verify_opts)
  end

  defp verify_mdoc_value(presentations, issuer_source, mdoc_context, verify_opts) when is_list(presentations) do
    presentations
    |> Enum.reduce_while({:ok, []}, fn presentation, {:ok, results} ->
      case verify_mdoc_one(presentation, issuer_source, mdoc_context, verify_opts) do
        {:ok, result} -> {:cont, {:ok, [result | results]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> reverse_list_result()
  end

  defp verify_mdoc_one(presentation, {:static, jwks}, mdoc_context, verify_opts) do
    verify_mdoc_with_keys(presentation, mdoc_context, jwks, verify_opts)
  end

  defp verify_mdoc_one(presentation, {:resolver, resolver}, mdoc_context, verify_opts) do
    with {:ok, doc_type} <- Mdoc.peek_doc_type(presentation),
         {:ok, jwks} <- resolve_mdoc_issuer_jwks(doc_type, resolver) do
      verify_mdoc_with_keys(presentation, mdoc_context, jwks, verify_opts)
    end
  end

  # `Attesto.Mdoc.verify_device_response/4` takes a single trusted JWK/PEM, not
  # a set, so a JWK Set (or issuer-key list) is tried one candidate at a time —
  # mirroring `Attesto.JWS.verify_strict/3`'s multi-candidate search, just at
  # the `Attesto.Mdoc` call boundary instead of inside COSE verification.
  defp verify_mdoc_with_keys(presentation, mdoc_context, trusted, verify_opts) do
    trusted
    |> mdoc_key_candidates()
    |> Enum.reduce_while({:error, :invalid_signature}, fn key, _acc ->
      case Mdoc.verify_device_response(presentation, mdoc_context, key, verify_opts) do
        {:ok, [document]} -> {:halt, {:ok, safe_mdoc_result(document)}}
        {:ok, _other} -> {:halt, {:error, :invalid_mdoc}}
        {:error, reason} -> {:cont, {:error, reason}}
      end
    end)
  end

  defp mdoc_key_candidates(%{"keys" => keys}) when is_list(keys), do: keys
  defp mdoc_key_candidates(keys) when is_list(keys), do: keys
  defp mdoc_key_candidates(%{} = jwk), do: [jwk]

  defp resolve_mdoc_issuer_jwks(doc_type, resolver) do
    case resolver.(doc_type) do
      {:ok, jwks} -> {:ok, jwks}
      {:error, reason} -> {:error, {:issuer, reason}}
      other -> {:error, {:issuer, {:invalid_resolver_result, other}}}
    end
  end

  defp safe_mdoc_result(verified) do
    %{
      doc_type: verified.doc_type,
      namespaces: verified.namespaces,
      device_namespaces: verified.device_namespaces,
      validity: verified.validity
    }
  end

  defp mdoc_context(nonce, audience, opts) do
    case Keyword.get(opts, :response_uri) do
      response_uri when is_binary(response_uri) and response_uri != "" ->
        {:ok, [client_id: audience, nonce: nonce, response_uri: response_uri]}

      _other ->
        {:error, :missing_response_uri}
    end
  end

  # ── format dispatch ─────────────────────────────────────────────────────

  defp entry_format(_id, presentation, formats) when map_size(formats) == 0, do: detect_format(presentation)

  defp entry_format(id, presentation, formats) do
    case Map.fetch(formats, id) do
      {:ok, format} -> {:ok, format}
      :error -> detect_format(presentation)
    end
  end

  defp detect_format(presentation) when is_binary(presentation), do: detect_format_value(presentation)
  defp detect_format([first | _rest]) when is_binary(first), do: detect_format_value(first)
  defp detect_format(_presentation), do: {:error, :unknown_format}

  defp detect_format_value(value) do
    cond do
      String.contains?(value, @separator) -> {:ok, :sd_jwt_vc}
      Regex.match?(@base64url, value) -> {:ok, :mso_mdoc}
      true -> {:error, :unknown_format}
    end
  end

  defp reverse_list_result({:ok, results}), do: {:ok, Enum.reverse(results)}
  defp reverse_list_result({:error, _reason} = error), do: error

  defp validate_vp_token!(vp_token) when is_map(vp_token), do: :ok

  defp validate_vp_token!(vp_token) do
    raise ArgumentError,
          "Attesto.VpToken.verify/2 expects a map; got #{inspect(vp_token)}"
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

  defp formats!(opts) do
    case Keyword.fetch(opts, :formats) do
      :error -> %{}
      {:ok, formats} when is_map(formats) -> normalize_formats!(formats)
      {:ok, formats} -> invalid_formats!(formats)
    end
  end

  defp normalize_formats!(formats) do
    if Enum.all?(formats, &valid_format_entry?/1) do
      Map.new(formats, fn {id, format} -> {id, Map.fetch!(@known_formats, format)} end)
    else
      invalid_formats!(formats)
    end
  end

  defp valid_format_entry?({id, format}) do
    is_binary(id) and id != "" and Map.has_key?(@known_formats, format)
  end

  defp invalid_formats!(formats) do
    raise ArgumentError,
          "Attesto.VpToken :formats must map query IDs to \"dc+sd-jwt\" or \"mso_mdoc\"; got #{inspect(formats)}"
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
