defmodule Attesto.SdJwtVc do
  @moduledoc """
  SD-JWT-based Verifiable Digital Credentials (SD-JWT VC), `draft-ietf-oauth-sd-jwt-vc-26`.

  The IETF profile of `Attesto.SdJwt` used by the EUDI wallet stack (and its
  High-Assurance Interoperability Profile, HAIP): an SD-JWT whose Issuer-signed
  JWT carries a credential *type* (`vct`), an issuer (`iss`), an optional holder
  key binding (`cnf`), an optional Token Status List reference (`status`), and
  the usual temporal claims, typed `dc+sd-jwt` in the JOSE `typ` header
  (legacy `vc+sd-jwt` is neither emitted nor accepted).

  This module adds the VC-specific claim rules on top of the base SD-JWT
  mechanism; the selective-disclosure machinery, recursive verification, and Key
  Binding JWT handling all come from `Attesto.SdJwt`.

    * `issue/2` — assemble and sign an SD-JWT VC: sets `iss`/`vct`/`iat` (and
      optional `exp`/`nbf`/`cnf`/`status`/`sub`), makes the chosen credential
      claims selectively disclosable, and stamps JOSE `typ` (`"dc+sd-jwt"`).
    * `verify/3` — verify the issuer signature (typed `dc+sd-jwt` /
      `application/dc+sd-jwt`), reconstruct the disclosed claims, and enforce
      the VC claim rules: `iss` and `vct` non-empty by default, `exp` (if
      present) not passed, `nbf` (if present) reached. Holder binding is a
      separate step - pass the returned `cnf` key to
      `Attesto.SdJwt.verify_key_binding/3` with the presentation's
      nonce/audience. Explicit certificate identity mode permits an omitted
      `iss` after the caller establishes certificate trust. Alternatively,
      `:trusted_certificates` opts into core path validation and SAN binding
      to a required `iss`.

  Conn-free and fail-closed, like the rest of attesto core.
  Credential status references are fetched and enforced by default through
  `Attesto.StatusList.fetch/3` and its bounded verified-token cache. Explicit
  `resolve_status: false` is for offline inspection; it must not be used to
  decide whether a credential is acceptable. A custom resolver can replace
  the transport while retaining signature and status enforcement.

  """

  alias Attesto.{JWS, MapParams, NumericDate, SdJwt, StatusList, X509}

  # draft-ietf-oauth-sd-jwt-vc-26: `dc+sd-jwt` only (stop emitting and accepting `vc+sd-jwt`).
  @typ "dc+sd-jwt"
  @accepted_typ ["dc+sd-jwt"]
  @clock_skew_seconds NumericDate.default_clock_skew_seconds()
  @max_issuer_segment_bytes 256 * 1_024

  # Registered SD-JWT VC claims MUST always be visible: a holder must not be
  # able to strip `cnf` (defeats holder-binding) or `status` (defeats
  # revocation) by simply omitting the Disclosure, nor any of the other
  # issuer-controlled claims. Subtracted from the effective disclosable list
  # below regardless of whether it came from `:disclosable` or the default.
  @issuance_visible_claim_names ~w(iss vct cnf status iat exp nbf sub)

  # SD-JWT VC permits `sub` and `iat` to be selectively disclosed. The other
  # profile claims must remain in the Issuer-signed JWT when present.
  @verification_visible_claim_names ~w(iss vct cnf status exp nbf)

  @type verified :: %{
          claims: map(),
          vct: String.t(),
          iss: String.t() | nil,
          cnf: map() | nil,
          key_binding_jwt: String.t() | nil,
          issuer_jwt: String.t(),
          disclosures: [String.t()]
        }

  @type verify_error ::
          SdJwt.verify_error()
          | :missing_iss
          | :invalid_issuer_identity
          | :disclosed_registered_claim
          | :missing_vct
          | :expired
          | :not_yet_valid
          | :invalid_cnf
          | {:credential_status, non_neg_integer()}
          | :credential_suspended
          | :credential_revoked
          | :invalid_status_reference
          | :invalid_status_list
          | :invalid_status_list_signature
          | :invalid_status_list_token
          | :status_list_uri_mismatch
          | :status_index_out_of_range
          | X509.verify_error()
          | :certificate_issuer_mismatch
          | term()

  @doc """
  Issue an SD-JWT VC.

  Required options:

    * `:iss` - the issuer identifier (its `.well-known/jwt-vc-issuer` or DID).
    * `:vct` - the verifiable credential type (a collision-resistant string/URI).
    * `:pem` - the issuer signing key (PEM).

  Optional:

    * `:claims` - the credential subject claims (a map). Defaults to `%{}`.
    * `:disclosable` - which of those claim names to make selectively
      disclosable. Defaults to all of `:claims`. Registered claims
      (`iss`/`vct`/`cnf`/`status`/`iat`/`exp`/`nbf`/`sub`) are never made
      disclosable even if listed here - they always remain visible, so a
      holder cannot strip holder-binding (`cnf`) or a status reference.
    * `:cnf` - the holder key-binding confirmation (RFC 7800), e.g.
      `%{"jwk" => holder_public_jwk}`. Included for later Key Binding.
    * `:status` - a Token Status List reference map, typically built with
      `Attesto.StatusList.reference/2`. Always visible when present.
    * `:iat` / `:exp` / `:nbf` / `:sub` - standard claims (unix seconds / string).
    * `:now` - clock reference for a defaulted `:iat`.
    * `:kid` - JOSE `kid` header. `:sd_alg` - SD hashing algorithm.
    * `:typ` - the SD-JWT VC media type stamped in the JOSE `typ` header;
      must be `"dc+sd-jwt"` (`draft-ietf-oauth-sd-jwt-vc-26`). Defaults to
      `"dc+sd-jwt"`.
    * `:x5c` - the issuer X.509 certificate chain (RFC 7515 §4.1.6): a non-empty
      list of base64 DER certificate strings, stamped in the JOSE `x5c` header so
      a verifier can bind the credential to a trusted issuer certificate (HAIP).
      Omitted when nil.

  Returns the SD-JWT VC Issuance string (no Key Binding JWT).
  """
  @spec issue(keyword(), keyword()) :: String.t()
  def issue(required, opts \\ []) when is_list(required) and is_list(opts) do
    opts = Keyword.merge(required, opts)
    iss = Keyword.fetch!(opts, :iss)
    vct = Keyword.fetch!(opts, :vct)
    # String-key the subject claims BEFORE merging the (always string-keyed)
    # registered claims: an atom-keyed collision (e.g. `claims: %{cnf: ...}`)
    # would otherwise survive the merge as a SEPARATE key from the string
    # `"cnf"`, signing a JWT with a duplicate JSON member — a last-wins verifier
    # could then bind to the wrong holder key. `Attesto.JwtVc` guards this the
    # same way.
    subject_claims = opts |> Keyword.get(:claims, %{}) |> MapParams.string_keyed_map()

    disclosable =
      opts
      |> Keyword.get(:disclosable, Map.keys(subject_claims))
      |> Enum.reject(&(to_string(&1) in @issuance_visible_claim_names))

    status = validate_status!(Keyword.get(opts, :status))

    registered =
      %{
        "iss" => iss,
        "vct" => vct,
        "iat" => Keyword.get(opts, :iat, NumericDate.now(opts, invalid_override: :fallback))
      }
      |> MapParams.put_optional("exp", Keyword.get(opts, :exp))
      |> MapParams.put_optional("nbf", Keyword.get(opts, :nbf))
      |> MapParams.put_optional("sub", Keyword.get(opts, :sub))
      |> MapParams.put_optional("cnf", Keyword.get(opts, :cnf))
      |> MapParams.put_optional("status", status)

    # Registered claims (iss/vct/cnf/status/temporal) are always visible; only
    # the subject claims may be selectively disclosed.
    claims = Map.merge(subject_claims, registered)

    signing_options =
      [
        disclosable: disclosable,
        typ: issue_typ!(Keyword.get(opts, :typ)),
        x5c: Keyword.get(opts, :x5c),
        sd_alg: Keyword.get(opts, :sd_alg, "sha-256")
      ]
      |> put_signing_source(opts)
      |> maybe_put_kid(opts)

    SdJwt.issue(claims, signing_options)
  end

  defp put_signing_source(options, opts) do
    case {Keyword.get(opts, :keystore), Keyword.get(opts, :pem)} do
      {keystore, nil} when is_atom(keystore) and not is_nil(keystore) -> Keyword.put(options, :keystore, keystore)
      {nil, pem} when is_binary(pem) and pem != "" -> Keyword.put(options, :pem, pem)
      {nil, nil} -> raise ArgumentError, "exactly one of :keystore or :pem is required"
      {_keystore, _pem} -> raise ArgumentError, "exactly one of :keystore or :pem is required"
    end
  end

  defp maybe_put_kid(options, opts) do
    case Keyword.fetch(opts, :kid) do
      {:ok, kid} -> Keyword.put(options, :kid, kid)
      :error -> options
    end
  end

  # draft-ietf-oauth-sd-jwt-vc-26 mandates `typ: "dc+sd-jwt"`.
  defp issue_typ!(nil), do: @typ
  defp issue_typ!(typ) when typ in @accepted_typ, do: typ

  defp issue_typ!(typ) do
    raise ArgumentError,
          "Attesto.SdJwtVc :typ must be one of #{inspect(@accepted_typ)}; got #{inspect(typ)}"
  end

  @doc """
  Verify an SD-JWT VC presentation and reconstruct the disclosed claims.

  `jwks` is the issuer's JWK Set (or `nil` with `:trusted_certificates`). Options
  are passed through to `Attesto.SdJwt.verify/3` (e.g. `:accepted_algs`), plus:

    * `:now` / `:max_age_seconds` - clock reference for the temporal checks.
    * `:issuer_identity` - defaults to `:claim`, requiring a nonempty `iss`.
      Set `:certificate` only after validating the issuer's certificate chain
      and supplying its verified leaf public key as `jwks`. This mode permits
      an omitted `iss` when the signed header contains `x5c`, as in the SD-JWT
      VC profile referenced by HAIP. A present malformed `iss` still fails.
      Without `:trusted_certificates`, the caller establishes certificate trust;
      an `x5c` header alone is never a trust decision.
    * `:trusted_certificates` - opt into X.509 key resolution with a nonempty
      list of DER trust anchors. The protected `x5c` chain is validated with
      `Attesto.X509.verify/2`; its leaf public key replaces `jwks` for signature
      verification. A required, signed `iss` must then pass
      `Attesto.X509.matches_issuer?/2`, including URI SAN precedence. This is
      the stricter binding policy documented there, not a requirement of all
      SD-JWT VC revisions. Empty or invalid anchors fail without falling back
      to `jwks`. This option also requires `iss` in `:certificate` identity mode.
    * `:haip` - with `:trusted_certificates`, defaults to `true`: refuse a
      self-signed leaf or an embedded configured trust anchor (HAIP §6.1.1).
      Set `false` for generic X.509 chain handling. The certificate purpose is
      always `:generic` for SD-JWT VC, regardless of any `:purpose` option.
    * `:certificate_trust` - with `:trusted_certificates`, an optional additional
      chain policy callback as in `Attesto.X509.verify/2`. It cannot bypass
      path validation, signature verification, or issuer binding. `:now` affects
      credential claims only; OTP uses system time for certificate validity.

  Returns `{:ok, %{claims:, vct:, iss:, cnf:, key_binding_jwt:, ...}}`. Holder
  binding is NOT checked here - if `cnf` is present and the presentation carries
  a Key Binding JWT, pass both to `Attesto.SdJwt.verify_key_binding/3` with the
  verifier's expected `nonce`/`audience`.

  A presentation is rejected if a supplied disclosure reconstructs one of the
  registered claims that must have remained visible. A digest does not reveal
  the name of an omitted disclosure, so a nonconforming issuer-hidden optional
  claim that the holder omits is indistinguishable from an absent optional
  claim. Verifiers must therefore trust the issuer to follow the profile's
  registered-claim visibility rule.
  """
  @spec verify(String.t(), map() | [map()] | list() | nil, keyword()) ::
          {:ok, verified()} | {:error, verify_error()}
  def verify(combined, jwks, opts \\ []) when is_binary(combined) do
    opts = Keyword.put_new(opts, :accepted_typ, @accepted_typ)

    with {:ok, issuer_keys, leaf} <- issuer_keys(combined, jwks, opts),
         {:ok, base} <- SdJwt.verify(combined, issuer_keys, opts),
         :ok <- check_registered_claim_visibility(base),
         {:ok, iss} <- credential_issuer(base, opts),
         :ok <- check_certificate_issuer(leaf, iss),
         {:ok, vct} <- require_string(base.claims, "vct", :missing_vct),
         :ok <- check_exp(base.claims, opts),
         :ok <- check_nbf(base.claims, opts),
         {:ok, cnf} <- check_cnf(base.claims),
         :ok <- check_status(base.claims, issuer_keys, opts) do
      {:ok,
       %{
         claims: base.claims,
         vct: vct,
         iss: iss,
         cnf: cnf,
         key_binding_jwt: base.key_binding_jwt,
         issuer_jwt: base.issuer_jwt,
         disclosures: base.disclosures
       }}
    end
  end

  defp issuer_keys(combined, jwks, opts) do
    if Keyword.has_key?(opts, :trusted_certificates) do
      certificate_issuer_keys(combined, opts)
    else
      {:ok, jwks, nil}
    end
  end

  defp certificate_issuer_keys(combined, _opts) when byte_size(combined) > @max_issuer_segment_bytes,
    do: {:error, :malformed}

  defp certificate_issuer_keys(combined, opts) do
    issuer_jwt = combined |> :binary.split("~") |> hd()
    trust_opts = opts |> Keyword.put_new(:haip, true) |> Keyword.put(:purpose, :generic)

    with {:ok, header} <-
           JWS.protected_header(issuer_jwt,
             crit_error: :malformed,
             max_compact_bytes: @max_issuer_segment_bytes
           ),
         {:ok, chain} <- X509.decode_x5c(Map.get(header, "x5c")),
         {:ok, verified} <- X509.verify(chain, trust_opts) do
      {:ok, verified.public_key, hd(chain)}
    end
  end

  defp check_certificate_issuer(nil, _iss), do: :ok
  defp check_certificate_issuer(_leaf, nil), do: {:error, :missing_iss}

  defp check_certificate_issuer(leaf, iss) do
    if X509.matches_issuer?(leaf, iss), do: :ok, else: {:error, :certificate_issuer_mismatch}
  end

  # ── claim rules ──────────────────────────────────────────────────────────

  defp check_registered_claim_visibility(base) do
    case JWS.peek_json(base.issuer_jwt, :payload, max_compact_bytes: @max_issuer_segment_bytes) do
      {:ok, signed_claims} ->
        disclosed_registered? =
          Enum.any?(@verification_visible_claim_names, fn claim ->
            Map.has_key?(base.claims, claim) and not Map.has_key?(signed_claims, claim)
          end)

        if disclosed_registered?, do: {:error, :disclosed_registered_claim}, else: :ok

      _invalid ->
        {:error, :invalid_signature}
    end
  end

  defp credential_issuer(base, opts) do
    case Keyword.get(opts, :issuer_identity, :claim) do
      :claim ->
        require_string(base.claims, "iss", :missing_iss)

      :certificate ->
        certificate_issuer(base)

      _invalid ->
        {:error, :invalid_issuer_identity}
    end
  end

  defp certificate_issuer(base) do
    with {:ok, header} <-
           JWS.peek_json(base.issuer_jwt, :protected, max_compact_bytes: @max_issuer_segment_bytes),
         [_ | _] <- Map.get(header, "x5c") do
      if Map.has_key?(base.claims, "iss"),
        do: require_string(base.claims, "iss", :missing_iss),
        else: {:ok, nil}
    else
      _invalid -> {:error, :missing_iss}
    end
  end

  # An omitted `cnf` means the credential has no holder binding. A present `cnf`
  # must be a non-empty object; a JSON null is refused rather than returned as an
  # unbound credential.
  defp check_cnf(claims) do
    case Map.fetch(claims, "cnf") do
      :error -> {:ok, nil}
      {:ok, cnf} when is_map(cnf) and map_size(cnf) > 0 -> {:ok, cnf}
      {:ok, _other} -> {:error, :invalid_cnf}
    end
  end

  defp check_status(claims, issuer_keys, opts) do
    case Map.fetch(claims, "status") do
      :error ->
        :ok

      {:ok, status} when is_map(status) and map_size(status) > 0 ->
        case StatusList.resolver(opts) do
          false ->
            :ok

          resolver when is_function(resolver, 1) or is_function(resolver, 2) ->
            status_opts =
              opts
              |> Keyword.take([
                :now,
                :accepted_algs,
                :trusted_certificates,
                :status_trusted_certificates,
                :haip,
                :certificate_trust,
                :cache_status
              ])
              |> Keyword.put(:format, :jwt)

            StatusList.check_status(status, resolver, issuer_keys, status_opts)
        end

      {:ok, _other} ->
        {:error, :invalid_status_reference}
    end
  end

  defp require_string(claims, key, error) do
    case Map.get(claims, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  # `exp`/`nbf` are OPTIONAL in SD-JWT VC, but when present must hold. A present
  # non-integer value is malformed and fails closed (mirrors `Attesto.Token`).
  defp check_exp(%{"exp" => exp}, opts) when is_integer(exp) do
    if NumericDate.not_expired?(
         exp,
         NumericDate.now(opts, invalid_override: :fallback),
         leeway: @clock_skew_seconds
       ),
       do: :ok,
       else: {:error, :expired}
  end

  defp check_exp(%{"exp" => _}, _opts), do: {:error, :expired}
  defp check_exp(_claims, _opts), do: :ok

  defp check_nbf(%{"nbf" => nbf}, opts) when is_integer(nbf) do
    if NumericDate.not_before_reached?(
         nbf,
         NumericDate.now(opts, invalid_override: :fallback),
         skew: @clock_skew_seconds
       ),
       do: :ok,
       else: {:error, :not_yet_valid}
  end

  defp check_nbf(%{"nbf" => _}, _opts), do: {:error, :not_yet_valid}
  defp check_nbf(_claims, _opts), do: :ok

  defp validate_status!(nil), do: nil
  defp validate_status!(status) when is_map(status), do: status

  defp validate_status!(status) do
    raise ArgumentError, ":status must be a map; got #{inspect(status)}"
  end
end
