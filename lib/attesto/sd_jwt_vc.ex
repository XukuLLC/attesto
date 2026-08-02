defmodule Attesto.SdJwtVc do
  @moduledoc """
  SD-JWT-based Verifiable Credentials (SD-JWT VC), draft-ietf-oauth-sd-jwt-vc.

  The IETF profile of `Attesto.SdJwt` used by the EUDI wallet stack (and its
  High-Assurance Interoperability Profile, HAIP): an SD-JWT whose Issuer-signed
  JWT carries a credential *type* (`vct`), an issuer (`iss`), an optional holder
  key binding (`cnf`), and the usual temporal claims, typed `vc+sd-jwt` in the
  JOSE `typ` header.

  This module adds the VC-specific claim rules on top of the base SD-JWT
  mechanism; the selective-disclosure machinery, recursive verification, and Key
  Binding JWT handling all come from `Attesto.SdJwt`.

    * `issue/2` — assemble and sign an SD-JWT VC: sets `iss`/`vct`/`iat` (and
      optional `exp`/`nbf`/`cnf`/`sub`), makes the chosen credential claims
      selectively disclosable, and stamps `typ: vc+sd-jwt`.
    * `verify/3` — verify the issuer signature (typed `vc+sd-jwt`), reconstruct
      the disclosed claims, and enforce the VC claim rules: `iss` and `vct`
      REQUIRED and non-empty, `exp` (if present) not passed, `nbf` (if present)
      reached. Holder binding is a separate step - pass the returned `cnf` key to
      `Attesto.SdJwt.verify_key_binding/3` with the presentation's nonce/audience.

  Conn-free and fail-closed, like the rest of attesto core.
  """

  alias Attesto.SdJwt

  # RFC-registered media type for an SD-JWT VC; the newer draft additionally
  # uses `dc+sd-jwt`. Accept both on verification, issue `vc+sd-jwt` by default.
  @typ "vc+sd-jwt"
  @accepted_typ ["vc+sd-jwt", "dc+sd-jwt"]
  @clock_skew_seconds 60

  @type verified :: %{
          claims: map(),
          vct: String.t(),
          iss: String.t(),
          cnf: map() | nil,
          key_binding_jwt: String.t() | nil,
          issuer_jwt: String.t(),
          disclosures: [String.t()]
        }

  @type verify_error :: SdJwt.verify_error() | :missing_iss | :missing_vct | :expired | :not_yet_valid

  @doc """
  Issue an SD-JWT VC.

  Required options:

    * `:iss` - the issuer identifier (its `.well-known/jwt-vc-issuer` or DID).
    * `:vct` - the verifiable credential type (a collision-resistant string/URI).
    * `:pem` - the issuer signing key (PEM).

  Optional:

    * `:claims` - the credential subject claims (a map). Defaults to `%{}`.
    * `:disclosable` - which of those claim names to make selectively
      disclosable. Defaults to all of `:claims`.
    * `:cnf` - the holder key-binding confirmation (RFC 7800), e.g.
      `%{"jwk" => holder_public_jwk}`. Included for later Key Binding.
    * `:iat` / `:exp` / `:nbf` / `:sub` - standard claims (unix seconds / string).
    * `:now` - clock reference for a defaulted `:iat`.
    * `:kid` - JOSE `kid` header. `:sd_alg` - SD hashing algorithm.

  Returns the SD-JWT VC Issuance string (no Key Binding JWT).
  """
  @spec issue(keyword(), keyword()) :: String.t()
  def issue(required, opts \\ []) when is_list(required) and is_list(opts) do
    opts = Keyword.merge(required, opts)
    iss = Keyword.fetch!(opts, :iss)
    vct = Keyword.fetch!(opts, :vct)
    subject_claims = Keyword.get(opts, :claims, %{})
    disclosable = Keyword.get(opts, :disclosable, Map.keys(subject_claims))

    registered =
      %{"iss" => iss, "vct" => vct, "iat" => Keyword.get(opts, :iat, now(opts))}
      |> put_present("exp", Keyword.get(opts, :exp))
      |> put_present("nbf", Keyword.get(opts, :nbf))
      |> put_present("sub", Keyword.get(opts, :sub))
      |> put_present("cnf", Keyword.get(opts, :cnf))

    # Registered claims (iss/vct/cnf/temporal) are always visible; only the
    # subject claims may be selectively disclosed.
    claims = Map.merge(subject_claims, registered)

    SdJwt.issue(claims,
      pem: Keyword.fetch!(opts, :pem),
      disclosable: disclosable,
      typ: @typ,
      kid: Keyword.get(opts, :kid),
      sd_alg: Keyword.get(opts, :sd_alg, "sha-256")
    )
  end

  @doc """
  Verify an SD-JWT VC presentation and reconstruct the disclosed claims.

  `jwks` is the issuer's JWK Set. Options are passed through to
  `Attesto.SdJwt.verify/3` (e.g. `:accepted_algs`), plus:

    * `:now` / `:max_age_seconds` - clock reference for the temporal checks.

  Returns `{:ok, %{claims:, vct:, iss:, cnf:, key_binding_jwt:, ...}}`. Holder
  binding is NOT checked here - if `cnf` is present and the presentation carries
  a Key Binding JWT, pass both to `Attesto.SdJwt.verify_key_binding/3` with the
  verifier's expected `nonce`/`audience`.
  """
  @spec verify(String.t(), map() | [map()] | list(), keyword()) ::
          {:ok, verified()} | {:error, verify_error()}
  def verify(combined, jwks, opts \\ []) when is_binary(combined) do
    opts = Keyword.put_new(opts, :accepted_typ, @accepted_typ)

    with {:ok, base} <- SdJwt.verify(combined, jwks, opts),
         {:ok, iss} <- require_string(base.claims, "iss", :missing_iss),
         {:ok, vct} <- require_string(base.claims, "vct", :missing_vct),
         :ok <- check_exp(base.claims, opts),
         :ok <- check_nbf(base.claims, opts) do
      {:ok,
       %{
         claims: base.claims,
         vct: vct,
         iss: iss,
         cnf: Map.get(base.claims, "cnf"),
         key_binding_jwt: base.key_binding_jwt,
         issuer_jwt: base.issuer_jwt,
         disclosures: base.disclosures
       }}
    end
  end

  # ── claim rules ──────────────────────────────────────────────────────────

  defp require_string(claims, key, error) do
    case Map.get(claims, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  # `exp`/`nbf` are OPTIONAL in SD-JWT VC, but when present must hold. A present
  # non-integer value is malformed and fails closed (mirrors `Attesto.Token`).
  defp check_exp(%{"exp" => exp}, opts) when is_integer(exp) do
    if exp > now(opts) - @clock_skew_seconds, do: :ok, else: {:error, :expired}
  end

  defp check_exp(%{"exp" => _}, _opts), do: {:error, :expired}
  defp check_exp(_claims, _opts), do: :ok

  defp check_nbf(%{"nbf" => nbf}, opts) when is_integer(nbf) do
    if nbf <= now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_nbf(%{"nbf" => _}, _opts), do: {:error, :not_yet_valid}
  defp check_nbf(_claims, _opts), do: :ok

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  defp now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
      n when is_integer(n) -> n
      _ -> DateTime.utc_now() |> DateTime.to_unix(:second)
    end
  end
end
