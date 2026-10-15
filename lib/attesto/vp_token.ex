defmodule Attesto.VpToken do
  @moduledoc """
  OID4VP `vp_token` verification for SD-JWT VC (`dc+sd-jwt`) and ISO mdoc
  (`mso_mdoc`) presentations (OID4VP §7).

  The response is a map from credential-query IDs to non-empty arrays of
  presentations. Verification is conn-free. SD-JWT VC entries delegate issuer
  signature, disclosure, VC claim, and holder Key Binding JWT checks to
  `Attesto.SdJwtVc` and `Attesto.SdJwt`; `mso_mdoc` entries delegate `Device`-
  `Response` and device-signature checks to `Attesto.Mdoc.verify_device_response/4`.

  Holder key binding is mandatory for SD-JWT VC: a credential without a
  `cnf.jwk` or a valid Key Binding JWT cannot satisfy an OID4VP request. mdoc
  presentations carry their own device-signature binding instead.

  ## Format dispatch

  Each query ID's format is resolved via the optional `:formats` option — a
  map of query ID to `"dc+sd-jwt"` or `"mso_mdoc"` — falling back to format
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

  # `Attesto.Mdoc` is referenced fully-qualified inside a `Code.ensure_loaded?/1`
  # guard (mdoc needs the optional `:cbor` dep), so it is deliberately not aliased.
  alias Attesto.{JWS, MapParams, PresentationRequest, SdJwt, SdJwtVc}

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
  `:accepted_algs` and `:enforce_fapi_alg_policy` are forwarded to SD-JWT
  issuer verification only, independently of the holder Key Binding JWT.
  `:expected_query_ids` identifies individually required entries;
  `:permitted_query_ids` can include optional requested entries.
  `:required_credential_sets` carries DCQL's AND-of-ORs response rule as a list
  of required sets, each containing one or more complete credential-ID options.
  For example, `[[["pid"], ["mdl"]], [["address"]]]` requires either `pid` or
  `mdl`, and also requires `address`. An explicit empty list represents a DCQL
  query whose credential sets are all optional and is the only policy that
  permits an empty VP Token. `constraints_from_dcql/1` embeds this policy in its
  result, so callers already storing that result as `:query_constraints` do not
  need to pass a second option. When omitted, the permitted set is derived from
  expected IDs, constraint keys, and required-set IDs. Entries outside that set
  are rejected before format detection or issuer lookup. Only low-level calls
  omitting all query-policy options accept arbitrary non-empty query IDs.
  Constraints remain enforced on optional entries when they are present.
  A query constraint permits multiple presentations only when its `:multiple`
  or `"multiple"` member is explicitly `true`; omission applies DCQL's default
  of one presentation.
  Malformed response maps and values return `{:error, :invalid_vp_token}`;
  malformed trusted options still raise `ArgumentError`.

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

  Each query ID must contain a non-empty list of presentation strings and
  produces a list of safe results, as required by OID4VP 1.0. The explicit
  `:legacy_scalar_values` option (default `false`) also accepts a non-empty
  presentation string and returns one safe result for that legacy entry.
  Raw JWTs and raw `DeviceResponse` bytes are never returned.
  """
  @spec verify(term(), keyword()) :: verify_result()
  def verify(vp_token, opts \\ []) do
    opts = MapParams.ensure_keyword!(opts)
    nonce = required_option!(opts, :nonce)
    audience = required_option!(opts, :audience)
    issuer_source = issuer_source!(opts)
    expected_query_ids = expected_query_ids!(opts)
    formats = formats!(opts)
    constraints = query_constraints!(opts)
    required_credential_sets = required_credential_sets!(opts, constraints)
    permitted_ids = permitted_query_ids!(opts, expected_query_ids, constraints, required_credential_sets)
    required_ids = required_query_ids(opts, expected_query_ids, constraints, required_credential_sets)
    legacy? = legacy_scalar_values!(opts)

    with :ok <- validate_presentations(vp_token, legacy?),
         :ok <- check_permitted_query_ids(vp_token, permitted_ids),
         :ok <- check_required_query_ids(vp_token, required_ids),
         :ok <- check_required_credential_sets(vp_token, required_credential_sets),
         :ok <- check_empty_response(vp_token, required_credential_sets),
         :ok <- check_presentation_counts(vp_token, constraints, legacy?) do
      verify_presentations(vp_token, issuer_source, nonce, audience, formats, constraints, opts)
    end
  end

  @doc """
  Derive per-query-id verification constraints from a DCQL query, for the
  `:query_constraints` option of `verify/2`.

  The query is first normalized with `Attesto.PresentationRequest.dcql_query/1`,
  so malformed empty constraints raise `ArgumentError` instead of being weakened.
  For each credential query this function extracts the requested `format`,
  cardinality, accepted credential type (`vct_values` for `dc+sd-jwt`,
  `doctype_value`/`doctype_values` for `mso_mdoc`), claims, and `claim_sets`.
  It also embeds the query's required credential-set options in every entry so
  the returned map is sufficient to enforce the complete DCQL response plan.
  `verify/2` enforces these after signature and holder binding. Query IDs absent
  from the returned map are unconstrained.
  """
  @spec constraints_from_dcql(map()) :: %{optional(String.t()) => map()}
  def constraints_from_dcql(dcql_query) when is_map(dcql_query) do
    # The query may reach us atom-keyed (a host passing an Elixir map to
    # `create_presentation_request`) or string-keyed (already JSON). The signed
    # request object normalizes atom keys, so the stored constraints MUST too -
    # otherwise an atom-keyed query would sign a constraint but store none,
    # leaving the response type-blind. Deep-stringify keys once, up front.
    dcql_query = dcql_query |> stringify_keys() |> PresentationRequest.dcql_query()
    credentials = Map.fetch!(dcql_query, "credentials")
    required_credential_sets = required_credential_sets_from_dcql(dcql_query, credentials)

    credentials
    |> reduce_constraints()
    |> Map.new(fn {id, constraint} ->
      {id, Map.put(constraint, :required_credential_sets, required_credential_sets)}
    end)
  end

  def constraints_from_dcql(_dcql_query), do: %{}

  defp reduce_constraints(credentials) do
    Enum.reduce(credentials, %{}, fn credential, acc ->
      case constraint_entry(credential) do
        {id, constraint} -> Map.put(acc, id, constraint)
        nil -> acc
      end
    end)
  end

  # Recursively stringify map keys (leaving values, including boolean atoms used
  # in claim `values`, untouched) so constraint derivation is key-representation
  # agnostic.
  defp stringify_keys(map) when is_map(map) and not is_struct(map) do
    Map.new(map, fn {key, value} -> {stringify_key(key), stringify_keys(value)} end)
  end

  defp stringify_keys(list) when is_list(list), do: Enum.map(list, &stringify_keys/1)
  defp stringify_keys(other), do: other

  defp stringify_key(key) when is_atom(key) and not is_boolean(key) and not is_nil(key), do: Atom.to_string(key)
  defp stringify_key(key), do: key

  defp constraint_entry(%{"id" => id} = credential) when is_binary(id) and id != "" do
    meta = credential |> Map.get("meta", %{}) |> ensure_map()

    {id,
     %{
       format: Map.get(credential, "format"),
       multiple: Map.get(credential, "multiple", false),
       vct_values: string_list(Map.get(meta, "vct_values")),
       doctype_values: mdoc_doctypes(meta),
       claims: parse_dcql_claims(Map.get(credential, "claims")),
       claim_sets: Map.get(credential, "claim_sets")
     }}
  end

  defp constraint_entry(_credential), do: nil

  defp ensure_map(value) when is_map(value), do: value
  defp ensure_map(_value), do: %{}

  # `mso_mdoc` DCQL meta uses the singular `doctype_value` (OID4VP); accept a
  # `doctype_values` list too for forward-compatibility.
  defp mdoc_doctypes(%{"doctype_value" => value}) when is_binary(value) and value != "", do: [value]
  defp mdoc_doctypes(%{"doctype_values" => values}), do: string_list(values)
  defp mdoc_doctypes(_meta), do: nil

  defp string_list(values) when is_list(values), do: values
  defp string_list(_values), do: nil

  defp parse_dcql_claims(claims) when is_list(claims) do
    Enum.map(claims, fn
      %{"path" => path} = claim when is_list(path) ->
        %{path: path, values: claim_values(claim)}
        |> MapParams.put_optional(:id, Map.get(claim, "id"))

      _claim ->
        :invalid
    end)
  end

  defp parse_dcql_claims(nil), do: nil
  defp parse_dcql_claims(_claims), do: :invalid

  defp claim_values(claim) do
    case Map.fetch(claim, "values") do
      {:ok, values} -> values
      :error -> nil
    end
  end

  defp required_credential_sets_from_dcql(dcql_query, credentials) do
    case Map.fetch(dcql_query, "credential_sets") do
      :error ->
        Enum.map(credentials, fn credential -> [[Map.fetch!(credential, "id")]] end)

      {:ok, credential_sets} ->
        credential_sets
        |> Enum.reject(&(Map.get(&1, "required", true) == false))
        |> Enum.map(&Map.fetch!(&1, "options"))
    end
  end

  defp verify_presentations(vp_token, issuer_source, nonce, audience, formats, constraints, opts) do
    verify_opts = Keyword.take(opts, [:now, :accepted_algs, :enforce_fapi_alg_policy])

    ctx = %{
      formats: formats,
      constraints: constraints,
      issuer_source: issuer_source,
      verify_opts: verify_opts,
      binding_opts: [nonce: nonce, audience: audience] ++ now_opts(opts),
      mdoc_context: mdoc_context(nonce, audience, opts)
    }

    Enum.reduce_while(vp_token, {:ok, %{}}, fn {id, presentation}, {:ok, results} ->
      case verify_entry(id, presentation, ctx) do
        {:ok, result} -> {:cont, {:ok, Map.put(results, id, result)}}
        {:error, reason} -> {:halt, {:error, {id, reason}}}
      end
    end)
  end

  defp verify_entry(id, presentation, ctx) do
    with {:ok, format} <- entry_format(id, presentation, ctx.formats),
         {:ok, result} <- verify_by_format(format, presentation, ctx) do
      # A validly-signed credential of the WRONG type (or wrong claim value) must
      # not satisfy a DCQL query for another type/value. Enforce the per-query
      # constraints derived from the request AFTER signature + holder binding.
      enforce_constraints(result, format, Map.get(ctx.constraints, id))
    end
  end

  defp verify_by_format(:sd_jwt_vc, presentation, ctx),
    do: verify_value(presentation, ctx.issuer_source, ctx.verify_opts, ctx.binding_opts)

  defp verify_by_format(:mso_mdoc, presentation, ctx),
    do: verify_mdoc_entry(presentation, ctx.issuer_source, ctx.verify_opts, ctx.mdoc_context)

  # ── DCQL constraint enforcement ──────────────────────────────────────────

  # No constraint stored for this query id: nothing to enforce (e.g. a direct
  # `VpToken.verify` caller that did not thread `:query_constraints`).
  defp enforce_constraints(result, _format, nil), do: {:ok, result}

  defp enforce_constraints(result, format, constraint) do
    # Bind the credential FORMAT to the query first. `format` is how the
    # presentation was actually verified (dispatched via `:formats` or, absent
    # that, shape detection): a `dc+sd-jwt` verifies as SD-JWT and would sail
    # past the mdoc `doctype` check (which never runs for an sd-jwt result), so a
    # verifier demanding an `mso_mdoc` must reject it on format alone.
    with :ok <- check_format(format, Map.get(constraint, :format)) do
      enforce_result_constraints(result, format, constraint)
    end
  end

  defp enforce_result_constraints(results, format, constraint) when is_list(results) do
    Enum.reduce_while(results, {:ok, results}, fn result, acc ->
      case check_result(result, format, constraint) do
        :ok -> {:cont, acc}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp enforce_result_constraints(result, format, constraint) do
    case check_result(result, format, constraint) do
      :ok -> {:ok, result}
      {:error, _reason} = error -> error
    end
  end

  # nil requested format => the query did not pin a format. Otherwise the
  # verified format MUST equal the one the DCQL query asked for; an unknown
  # requested format maps to no atom and so fails closed.
  defp check_format(_actual, nil), do: :ok

  defp check_format(actual, requested) do
    if Map.get(@known_formats, requested) == actual, do: :ok, else: {:error, :format_mismatch}
  end

  defp check_result(%{vct: vct, claims: claims}, :sd_jwt_vc, constraint) do
    with :ok <- check_type(vct, Map.get(constraint, :vct_values), :vct_mismatch) do
      check_claims(claims, Map.get(constraint, :claims), Map.get(constraint, :claim_sets), :sd_jwt_vc)
    end
  end

  defp check_result(%{doc_type: doc_type, namespaces: namespaces}, :mso_mdoc, constraint) do
    with :ok <- check_type(doc_type, Map.get(constraint, :doctype_values), :doctype_mismatch) do
      check_claims(namespaces, Map.get(constraint, :claims), Map.get(constraint, :claim_sets), :mso_mdoc)
    end
  end

  # A constraint exists for this id but the result shape doesn't match the
  # format's expected shape - unreachable with the current result constructors,
  # but fail closed rather than silently accept an unenforceable presentation.
  defp check_result(_result, _format, _constraint), do: {:error, :unenforceable_constraint}

  # nil means the query did not constrain the type. An empty list is malformed
  # DCQL and must fail closed rather than becoming an "accept any" policy.
  defp check_type(_actual, nil, _error), do: :ok

  defp check_type(actual, allowed, error) when is_list(allowed) and allowed != [] do
    if actual in allowed, do: :ok, else: {:error, error}
  end

  defp check_type(_actual, _malformed, error), do: {:error, error}

  defp check_claims(_disclosed, nil, nil, _format), do: :ok

  defp check_claims(disclosed, claims, nil, format) when is_list(claims) and claims != [] do
    Enum.reduce_while(claims, :ok, fn claim, :ok ->
      case check_claim(disclosed, claim, format) do
        :ok -> {:cont, :ok}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp check_claims(disclosed, claims, claim_sets, format)
       when is_list(claims) and claims != [] and is_list(claim_sets) and claim_sets != [] do
    claims_by_id = Map.new(claims, &{Map.get(&1, :id), &1})

    if Enum.any?(claim_sets, &claim_option_satisfied?(&1, claims_by_id, disclosed, format)) do
      :ok
    else
      {:error, {:claim_set_unsatisfied, claim_sets}}
    end
  end

  defp check_claims(_disclosed, _claims, _claim_sets, _format), do: {:error, :invalid_claim_constraints}

  defp claim_option_satisfied?(option, claims_by_id, disclosed, format) when is_list(option) and option != [] do
    Enum.all?(option, fn id ->
      case Map.fetch(claims_by_id, id) do
        {:ok, claim} -> check_claim(disclosed, claim, format) == :ok
        :error -> false
      end
    end)
  end

  defp claim_option_satisfied?(_option, _claims_by_id, _disclosed, _format), do: false

  # Every requested claim must resolve in the disclosed credential. A `values`
  # restriction additionally requires every selected value to be an exact member
  # of the requested set; malformed or empty value sets fail closed.
  defp check_claim(disclosed, %{path: path} = claim, format) when is_list(path) do
    values = Map.get(claim, :values)

    case resolve_path(disclosed, path, format) do
      {:ok, _selected} when is_nil(values) ->
        :ok

      {:ok, selected} when is_list(values) and values != [] ->
        if selected_values_allowed?(selected, values),
          do: :ok,
          else: {:error, {:claim_value_mismatch, path}}

      {:ok, _selected} ->
        {:error, {:claim_value_mismatch, path}}

      :error when is_list(values) and values != [] ->
        {:error, {:claim_value_mismatch, path}}

      :error ->
        {:error, {:claim_missing, path}}
    end
  end

  defp check_claim(_disclosed, _claim, _format), do: {:error, :invalid_claim_constraints}

  defp selected_values_allowed?(selected, allowed) do
    Enum.all?(selected, fn selected_value -> Enum.any?(allowed, &(&1 === selected_value)) end)
  end

  defp resolve_path(map, [namespace, element], :mso_mdoc) when is_binary(namespace) and is_binary(element) do
    resolve_json_path([map], [namespace, element])
  end

  defp resolve_path(_map, _path, :mso_mdoc), do: :error
  defp resolve_path(map, path, :sd_jwt_vc) when is_list(path) and path != [], do: resolve_json_path([map], path)
  defp resolve_path(_map, _path, _format), do: :error

  defp resolve_json_path(selected, []), do: if(selected == [], do: :error, else: {:ok, selected})

  defp resolve_json_path(selected, [component | rest]) do
    with {:ok, next} <- select_path_component(selected, component),
         false <- next == [] do
      resolve_json_path(next, rest)
    else
      _error_or_empty -> :error
    end
  end

  defp select_path_component(selected, key) when is_binary(key) do
    if Enum.all?(selected, &(is_map(&1) and not is_struct(&1))) do
      {:ok,
       Enum.flat_map(selected, fn map ->
         case Map.fetch(map, key) do
           {:ok, value} -> [value]
           :error -> []
         end
       end)}
    else
      :error
    end
  end

  defp select_path_component(selected, nil) do
    if Enum.all?(selected, &is_list/1), do: {:ok, Enum.flat_map(selected, & &1)}, else: :error
  end

  defp select_path_component(selected, index) when is_integer(index) and index >= 0 do
    if Enum.all?(selected, &is_list/1) do
      {:ok,
       Enum.flat_map(selected, fn list ->
         case Enum.fetch(list, index) do
           {:ok, value} -> [value]
           :error -> []
         end
       end)}
    else
      :error
    end
  end

  defp select_path_component(_selected, _component), do: :error

  defp verify_mdoc_entry(_presentation, _issuer_source, _verify_opts, {:error, reason}), do: {:error, reason}

  defp verify_mdoc_entry(presentation, issuer_source, verify_opts, {:ok, mdoc_context}) do
    verify_mdoc_value(presentation, issuer_source, mdoc_context, verify_opts)
  end

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

  # mdoc (ISO 18013-5) verification needs the optional `:cbor` dependency. When
  # it is absent `Attesto.Mdoc` is a raising stub (typed `none()`), so gate the
  # whole mdoc verification path the same way: a build without `:cbor` fails an
  # mdoc presentation closed with `:mdoc_unsupported` instead of crashing — and
  # at compile time there are no unreachable-clause warnings against the stub.
  if Code.ensure_loaded?(CBOR) do
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
      with {:ok, doc_type} <- Attesto.Mdoc.peek_doc_type(presentation),
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
      |> Enum.reduce_while(:no_candidate, fn key, candidate_error ->
        case Attesto.Mdoc.verify_device_response(presentation, mdoc_context, key, verify_opts) do
          {:ok, [document]} ->
            {:halt, {:ok, safe_mdoc_result(document)}}

          {:ok, _other} ->
            {:halt, {:error, :invalid_mdoc}}

          {:error, reason} when reason in [:invalid_key, :invalid_signature] ->
            {:cont, remember_mdoc_candidate_error(candidate_error, reason)}

          {:error, reason} ->
            {:halt, {:error, reason}}
        end
      end)
      |> finalize_mdoc_candidate_result()
    end

    defp mdoc_key_candidates(%{"keys" => keys}) when is_list(keys), do: keys
    defp mdoc_key_candidates(keys) when is_list(keys), do: keys
    defp mdoc_key_candidates(%{} = jwk), do: [jwk]
    defp mdoc_key_candidates(pem) when is_binary(pem), do: [pem]
    defp mdoc_key_candidates(nil), do: []
    defp mdoc_key_candidates(_other), do: []

    defp remember_mdoc_candidate_error(:no_candidate, reason), do: {:error, reason}
    defp remember_mdoc_candidate_error({:error, :invalid_key}, :invalid_signature), do: {:error, :invalid_signature}
    defp remember_mdoc_candidate_error(error, _reason), do: error

    defp finalize_mdoc_candidate_result(:no_candidate), do: {:error, :invalid_signature}
    defp finalize_mdoc_candidate_result(result), do: result

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
  else
    defp verify_mdoc_value(_presentation, _issuer_source, _mdoc_context, _verify_opts), do: {:error, :mdoc_unsupported}
  end

  defp mdoc_context(nonce, audience, opts) do
    case Keyword.get(opts, :response_uri) do
      response_uri when is_binary(response_uri) and response_uri != "" ->
        context = [client_id: audience, nonce: nonce, response_uri: response_uri]

        # For an encrypted (`direct_post.jwt`) mdoc response the handover binds to
        # the verifier's response-encryption JWK thumbprint; unencrypted omits it.
        context =
          case Keyword.get(opts, :response_encryption_jwk) do
            jwk when is_map(jwk) -> Keyword.put(context, :response_encryption_jwk, jwk)
            _other -> context
          end

        {:ok, context}

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

  defp query_constraints!(opts) do
    case Keyword.fetch(opts, :query_constraints) do
      :error ->
        %{}

      {:ok, constraints} when is_map(constraints) ->
        constraints

      {:ok, constraints} ->
        raise ArgumentError,
              "Attesto.VpToken :query_constraints must be a map of query ID to constraint; got #{inspect(constraints)}"
    end
  end

  defp required_credential_sets!(opts, constraints) do
    embedded = embedded_required_credential_sets!(constraints)

    case Keyword.fetch(opts, :required_credential_sets) do
      {:ok, required_sets} ->
        required_sets = validate_required_credential_sets!(required_sets)

        if embedded in [:absent, required_sets] do
          required_sets
        else
          raise ArgumentError, "Attesto.VpToken :required_credential_sets conflicts with :query_constraints"
        end

      :error ->
        embedded
    end
  end

  defp embedded_required_credential_sets!(constraints) do
    policies =
      constraints
      |> Map.values()
      |> Enum.flat_map(fn
        %{required_credential_sets: required_sets} -> [required_sets]
        %{"required_credential_sets" => required_sets} -> [required_sets]
        _constraint -> []
      end)
      |> Enum.uniq()

    case policies do
      [] -> :absent
      [required_sets] -> validate_required_credential_sets!(required_sets)
      _conflicting -> raise ArgumentError, "Attesto.VpToken constraints contain conflicting DCQL response policies"
    end
  end

  defp validate_required_credential_sets!(required_sets) when is_list(required_sets) do
    if Enum.all?(required_sets, &valid_required_credential_set?/1) do
      required_sets
    else
      invalid_required_credential_sets!()
    end
  end

  defp validate_required_credential_sets!(_required_sets), do: invalid_required_credential_sets!()

  defp valid_required_credential_set?(options) when is_list(options) and options != [] do
    Enum.all?(options, fn option ->
      is_list(option) and option != [] and
        Enum.all?(option, &(is_binary(&1) and &1 != "")) and Enum.uniq(option) == option
    end)
  end

  defp valid_required_credential_set?(_options), do: false

  defp invalid_required_credential_sets! do
    raise ArgumentError,
          "Attesto.VpToken :required_credential_sets must be a list of non-empty option lists " <>
            "containing non-empty credential-ID lists"
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

  defp permitted_query_ids!(opts, expected, constraints, required_credential_sets) do
    requested = Enum.uniq(expected ++ Map.keys(constraints) ++ credential_set_ids(required_credential_sets))

    case Keyword.fetch(opts, :permitted_query_ids) do
      {:ok, ids} ->
        validate_permitted_query_ids!(ids, requested)

      :error ->
        if Keyword.has_key?(opts, :expected_query_ids) or Keyword.has_key?(opts, :query_constraints) or
             Keyword.has_key?(opts, :required_credential_sets),
           do: requested,
           else: :unrestricted
    end
  end

  defp credential_set_ids(:absent), do: []

  defp credential_set_ids(required_sets) do
    required_sets
    |> List.flatten()
    |> Enum.uniq()
  end

  defp validate_permitted_query_ids!(ids, requested) do
    if is_list(ids) and Enum.all?(ids, &(is_binary(&1) and &1 != "")) and
         Enum.uniq(ids) == ids and Enum.all?(requested, &(&1 in ids)) do
      ids
    else
      raise ArgumentError, ":permitted_query_ids must contain every required or constrained query ID"
    end
  end

  defp required_query_ids(opts, expected, constraints, required_credential_sets) do
    if Keyword.has_key?(opts, :expected_query_ids) or Keyword.has_key?(opts, :permitted_query_ids),
      do: expected,
      else: if(required_credential_sets == :absent, do: Map.keys(constraints), else: [])
  end

  defp check_permitted_query_ids(_vp_token, :unrestricted), do: :ok

  defp check_permitted_query_ids(vp_token, permitted) do
    vp_token
    |> Map.keys()
    |> Enum.reject(&(&1 in permitted))
    |> Enum.sort()
    |> case do
      [] -> :ok
      unexpected -> {:error, {:unexpected_query_ids, unexpected}}
    end
  end

  defp check_required_query_ids(vp_token, required) do
    case missing_query_ids(vp_token, required) do
      [] -> :ok
      missing -> {:error, {:missing_credentials, missing}}
    end
  end

  defp check_required_credential_sets(_vp_token, :absent), do: :ok

  defp check_required_credential_sets(vp_token, required_sets) do
    missing =
      required_sets
      |> Enum.with_index()
      |> Enum.reject(fn {options, _index} ->
        Enum.any?(options, fn option -> Enum.all?(option, &Map.has_key?(vp_token, &1)) end)
      end)
      |> Enum.map(&elem(&1, 1))

    if missing == [], do: :ok, else: {:error, {:unsatisfied_credential_sets, missing}}
  end

  defp check_empty_response(vp_token, :absent) when map_size(vp_token) == 0, do: {:error, :invalid_vp_token}
  defp check_empty_response(_vp_token, _required_credential_sets), do: :ok

  defp check_presentation_counts(vp_token, constraints, legacy?) do
    Enum.reduce_while(vp_token, :ok, fn {id, presentations}, :ok ->
      case {presentation_count(presentations, legacy?), Map.get(constraints, id)} do
        {count, constraint} when count > 1 and is_map(constraint) ->
          presentation_count_reduction(id, multiple_presentations_allowed?(constraint))

        _allowed ->
          {:cont, :ok}
      end
    end)
  end

  defp presentation_count_reduction(_id, true), do: {:cont, :ok}

  defp presentation_count_reduction(id, false), do: {:halt, {:error, {id, :multiple_presentations_not_allowed}}}

  defp multiple_presentations_allowed?(constraint) do
    case {Map.fetch(constraint, :multiple), Map.fetch(constraint, "multiple")} do
      {{:ok, true}, :error} -> true
      {:error, {:ok, true}} -> true
      {{:ok, true}, {:ok, true}} -> true
      _absent_or_invalid -> false
    end
  end

  defp presentation_count(presentation, true) when is_binary(presentation), do: 1
  defp presentation_count(presentations, _legacy?) when is_list(presentations), do: length(presentations)

  defp legacy_scalar_values!(opts) do
    case Keyword.get(opts, :legacy_scalar_values, false) do
      value when is_boolean(value) -> value
      _invalid -> raise ArgumentError, "Attesto.VpToken :legacy_scalar_values must be true or false"
    end
  end

  defp validate_presentations(vp_token, legacy?) when is_map(vp_token) and not is_struct(vp_token) do
    if Enum.all?(vp_token, fn {id, value} ->
         is_binary(id) and id != "" and valid_presentation?(value, legacy?)
       end),
       do: :ok,
       else: {:error, :invalid_vp_token}
  end

  defp validate_presentations(_vp_token, _legacy?), do: {:error, :invalid_vp_token}

  defp valid_presentation?(presentation, true) when is_binary(presentation) and presentation != "", do: true

  defp valid_presentation?(presentations, _legacy?) when is_list(presentations) and presentations != [] do
    Enum.all?(presentations, &(is_binary(&1) and &1 != ""))
  end

  defp valid_presentation?(_presentation, _legacy?), do: false

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
