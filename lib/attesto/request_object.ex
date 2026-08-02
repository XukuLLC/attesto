defmodule Attesto.RequestObject do
  @moduledoc """
  Signed OpenID Connect Request Object verification (JAR, RFC 9101 / OIDC §6.1).

  This module verifies a compact JWT request object against trusted client
  JWKs supplied by the host. It deliberately rejects unsigned request objects:
  a host that wants request objects is opting into integrity protection, not a
  second unsigned parameter encoding.
  """

  alias Attesto.JWS
  alias Attesto.SigningAlg

  @clock_skew_seconds 60

  @type verify_opts :: [
          {:now, DateTime.t() | non_neg_integer()}
          | {:issuer, String.t() | nil}
          | {:audience, String.t() | [String.t()]}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:enforce_fapi_alg_policy, boolean()}
          | {:require_nbf, boolean()}
          | {:max_nbf_age_seconds, pos_integer() | nil}
          | {:require_exp, boolean()}
          | {:require_iat, boolean()}
          | {:require_jti, boolean()}
          | {:require_client_id_claim, boolean()}
          | {:max_lifetime_seconds, pos_integer() | nil}
          | {:accepted_typ, [String.t() | nil] | nil}
          | {:string_valued_claims, [String.t()]}
        ]

  @type verify_error ::
          :invalid_request_object
          | :request_not_supported
          | :invalid_signature
          | :invalid_issuer
          | :invalid_audience
          | :invalid_typ
          | :expired
          | :not_yet_valid
          | :unsupported_critical_header

  @doc """
  Verify and return a string-keyed parameter map from a signed request object.

  The object must carry `iss`, `client_id`, and `aud`. `iss` must match the
  object's `client_id` and the caller-supplied `:issuer`; `aud` must match the
  caller-supplied `:audience`.

  Opts implementing the RFC 9101 / FAPI Message Signing 2.0 §5.3.1 strict-JAR
  policy. Every one defaults to the lenient JAR/OIDC §6.1 behaviour, so a
  caller that passes none observes no change:

    * `:accepted_algs` - JOSE algorithms a candidate trusted key may use.
      Defaults to `SigningAlg.fapi_algs/0` (PS256, ES256, EdDSA over Ed25519,
      and explicit Ed25519).
    * `:enforce_fapi_alg_policy` - additionally enforce the FAPI key/algorithm
      policy, rejecting RSA moduli below 2048 bits and legacy `EdDSA` over
      Ed448. Defaults to `true` when `:accepted_algs` is omitted and `false`
      when the caller supplies an explicit non-FAPI algorithm policy. Composed
      FAPI profiles that narrow the allowlist must pass `true`.
    * `:require_nbf` - when `true`, reject an object without an `nbf` claim.
      Defaults to `false`. (RFC 9101 / FAPI Message Signing 2.0 §5.3.1.)
    * `:max_nbf_age_seconds` - when set, reject an `nbf` older than `now - N`.
      Defaults to `nil` (no lower bound).
    * `:require_exp` - when `true`, reject an object without an `exp` claim.
      Defaults to `false`.
    * `:require_iat` - when `true`, reject an object without a valid `iat`
      NumericDate claim. Defaults to `false`. (CIBA Core §7.1.1 makes `iat`
      REQUIRED in a signed authentication request.)
    * `:require_jti` - when `true`, reject an object without a non-empty
      string `jti` claim. Defaults to `false`. (CIBA Core §7.1.1 makes `jti`
      REQUIRED; replay tracking against it is the caller's concern.)
    * `:require_client_id_claim` - when `false`, skip the requirement that the
      object carry a `client_id` claim equal to `iss`. RFC 9101 request
      objects carry `client_id`; a CIBA signed authentication request
      (CIBA Core §7.1.1) does not - its `iss` alone names the client and is
      still matched against the caller-supplied `:issuer`. Defaults to `true`
      (the RFC 9101 behaviour).
    * `:max_lifetime_seconds` - when set, require valid `nbf` and `exp`
      NumericDate anchors and reject an `exp` greater than `nbf + N`. Defaults
      to `nil` (no lifetime bound).
    * `:accepted_typ` - when a list, require the JOSE header `typ` to be a
      member; `nil` in the list permits an absent `typ`. Defaults to `nil`,
      which accepts any `typ` including its absence.
    * `:string_valued_claims` - when a list of claim names, each named claim
      that is present MUST be a JSON string, else `:invalid_request_object`.
      This runs BEFORE the claim → parameter coercion, so a non-string value
      (number, boolean, array, object) is rejected rather than stringified /
      space-joined / JSON-encoded, and a malformed value can never reach
      `claims_to_params/1`'s coercion (so it cannot raise). Defaults to `[]`
      (no typing constraint - the lenient JAR/OIDC §6.1 coercion). CIBA Core
      §7.1.1 uses this to require its known authentication-request parameters
      be JSON strings in a signed request; RFC 9101 JAR leaves it unset.
  """
  @spec verify(String.t(), map() | [map()] | map(), verify_opts()) :: {:ok, map()} | {:error, verify_error()}
  def verify(jwt, trusted_jwks, opts \\ []) do
    case verify_with_claims(jwt, trusted_jwks, opts) do
      {:ok, params, _claims} -> {:ok, params}
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Like `verify/3`, but also returns the raw verified JWT claims alongside the
  parameter map: `{:ok, params, claims}`.

  A profile that must act on reserved claims the parameter map deliberately
  drops - CIBA Core §7.1.1 needs the signed request's `jti` and `exp` to
  implement replay defense at the host boundary - uses this to read them
  without decoding/verifying the JWT a second time. `params` is identical to
  what `verify/3` returns.
  """
  @spec verify_with_claims(String.t(), map() | [map()] | map(), verify_opts()) ::
          {:ok, map(), map()} | {:error, verify_error()}
  def verify_with_claims(jwt, trusted_jwks, opts \\ [])

  def verify_with_claims(jwt, trusted_jwks, opts) when is_binary(jwt) and is_list(opts) do
    with {:ok, header} <- peek_header(jwt),
         :ok <- check_crit(header),
         :ok <- check_supported_alg(header),
         :ok <- check_typ(header, Keyword.get(opts, :accepted_typ)),
         {:ok, claims} <- verify_signature(jwt, header, trusted_jwks, opts),
         :ok <- check_no_nested_request(claims),
         :ok <- check_claim_issuer(claims, opts),
         :ok <- check_issuer(claims, Keyword.get(opts, :issuer)),
         :ok <- check_audience(claims, Keyword.get(opts, :audience)),
         :ok <- check_expiry(claims, opts),
         :ok <- check_iat(claims, opts),
         :ok <- check_nbf(claims, opts),
         :ok <- check_jti(claims, opts),
         :ok <- check_lifetime(claims, opts),
         :ok <- check_string_valued_claims(claims, opts) do
      {:ok, claims_to_params(claims), claims}
    end
  end

  def verify_with_claims(_jwt, _trusted_jwks, _opts), do: {:error, :invalid_request_object}

  defp verify_signature(jwt, header, trusted_jwks, opts) do
    accepted_algs = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())

    enforce_fapi_policy =
      Keyword.get(opts, :enforce_fapi_alg_policy, not Keyword.has_key?(opts, :accepted_algs))

    case candidates(trusted_jwks, Map.get(header, "kid"), accepted_algs, enforce_fapi_policy) do
      [] -> {:error, :invalid_signature}
      jwks -> verify_against_any(jwks, jwt)
    end
  end

  defp candidates(trusted_jwks, header_kid, accepted_algs, enforce_fapi_policy) do
    trusted_jwks
    |> normalize_jwks()
    |> Enum.map(fn jwk_map ->
      jwk = JOSE.JWK.from_map(jwk_map)
      alg = Map.get(jwk_map, "alg") || SigningAlg.infer(jwk)
      {Map.get(jwk_map, "kid"), SigningAlg.validate_for_key!(alg, jwk), jwk}
    end)
    |> Enum.filter(fn {_kid, alg, jwk} ->
      alg in accepted_algs and (not enforce_fapi_policy or SigningAlg.fapi_compatible?(alg, jwk))
    end)
    |> filter_by_kid(header_kid)
  rescue
    _ -> []
  end

  defp normalize_jwks(%{"keys" => keys}) when is_list(keys), do: keys
  defp normalize_jwks(keys) when is_list(keys), do: keys
  defp normalize_jwks(%{} = jwk), do: [jwk]
  defp normalize_jwks(_), do: []

  defp filter_by_kid(keyed, nil), do: keyed
  defp filter_by_kid(keyed, kid), do: Enum.filter(keyed, fn {k, _alg, _jwk} -> k == kid end)

  defp verify_against_any(candidates, jwt) do
    Enum.reduce_while(candidates, {:error, :invalid_signature}, fn {_kid, alg, jwk}, acc ->
      case JOSE.JWT.verify_strict(jwk, [alg], jwt) do
        {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:halt, {:ok, claims}}
        {false, _jwt, _jws} -> {:cont, acc}
        _other -> {:halt, {:error, :invalid_request_object}}
      end
    end)
  end

  # RFC 9101 §4: "The Request Object MAY contain... [it] MUST NOT contain the
  # request or request_uri parameters." A nested `request`/`request_uri` is a
  # malformed request object, not a parameter to silently strip - reject it so a
  # recursion/smuggle attempt fails closed at the verifier rather than being
  # quietly dropped and later rejected with the wrong error downstream.
  defp check_no_nested_request(claims) do
    if Map.has_key?(claims, "request") or Map.has_key?(claims, "request_uri") do
      {:error, :invalid_request_object}
    else
      :ok
    end
  end

  # RFC 9101 request objects carry a `client_id` claim that must equal `iss`.
  # A profile whose objects name the client through `iss` alone (CIBA Core
  # §7.1.1) opts out with `require_client_id_claim: false`; `iss` is still
  # matched against the caller-supplied `:issuer` in `check_issuer/2`.
  defp check_claim_issuer(claims, opts) do
    if Keyword.get(opts, :require_client_id_claim, true) do
      case claims do
        %{"client_id" => client_id, "iss" => client_id} when is_binary(client_id) and client_id != "" -> :ok
        _ -> {:error, :invalid_issuer}
      end
    else
      :ok
    end
  end

  defp check_issuer(_claims, nil), do: {:error, :invalid_issuer}
  defp check_issuer(%{"iss" => iss}, iss), do: :ok
  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  defp check_audience(_claims, nil), do: {:error, :invalid_audience}

  defp check_audience(%{"aud" => aud}, expected) when is_list(expected) do
    if valid_aud_claim?(aud) and aud_intersects?(aud, expected),
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_audience(%{"aud" => aud}, expected) when is_binary(expected),
    do: check_audience(%{"aud" => aud}, [expected])

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  # RFC 7519 §4.1.3: `aud` is a StringOrURI or an array of StringOrURI. A list
  # carrying any non-string member is a malformed audience claim - reject it
  # rather than accepting on a single matching member (matches the hardened
  # Token/IDToken/JARM audience handling).
  defp valid_aud_claim?(aud) when is_binary(aud), do: true
  defp valid_aud_claim?([_ | _] = aud), do: Enum.all?(aud, &is_binary/1)
  defp valid_aud_claim?(_aud), do: false

  # Only ever called after `valid_aud_claim?/1` confirms `aud` is a binary or a
  # non-empty list of binaries, so those two clauses are exhaustive here.
  defp aud_intersects?(aud, expected) when is_binary(aud), do: aud in expected
  defp aud_intersects?(aud, expected) when is_list(aud), do: Enum.any?(aud, &(&1 in expected))

  defp check_expiry(%{"exp" => exp}, opts) when is_integer(exp) and exp >= 0 do
    if exp > unix_now(opts), do: :ok, else: {:error, :expired}
  end

  defp check_expiry(_claims, _opts), do: :ok

  defp check_iat(%{"iat" => iat}, opts) when is_integer(iat) and iat >= 0 do
    if iat <= unix_now(opts) + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_iat(%{"iat" => _}, _opts), do: {:error, :not_yet_valid}

  # Under `require_iat: true` (CIBA Core §7.1.1) a missing `iat` is a failure;
  # a present one was validated above.
  defp check_iat(_claims, opts) do
    if Keyword.get(opts, :require_iat, false) == true,
      do: {:error, :invalid_request_object},
      else: :ok
  end

  # Under `require_jti: true` (CIBA Core §7.1.1) the object must carry a
  # non-empty string `jti`. Uniqueness/replay tracking is the caller's concern;
  # this verifier is stateless.
  defp check_jti(claims, opts) do
    if Keyword.get(opts, :require_jti, false) == true do
      case Map.get(claims, "jti") do
        jti when is_binary(jti) and jti != "" -> :ok
        _ -> {:error, :invalid_request_object}
      end
    else
      :ok
    end
  end

  # CIBA Core §7.1.1: the named authentication-request parameters MUST be JSON
  # strings in a signed request (only `requested_expiry` may additionally be a
  # number, and extension claims may be other JSON types - neither is listed
  # here). Enforced BEFORE `claims_to_params/1`, so a non-string known
  # parameter (number/boolean/array/object) is an `invalid_request_object`
  # rather than a silently coerced value, and an array-containing-an-object can
  # never reach the coercion's `Enum.join/2` (which would raise). Default `[]`
  # (RFC 9101 JAR) applies no constraint and leaves the coercion untouched.
  defp check_string_valued_claims(claims, opts) do
    case Keyword.get(opts, :string_valued_claims, []) do
      [_ | _] = names ->
        if Enum.all?(names, &string_valued_claim?(claims, &1)),
          do: :ok,
          else: {:error, :invalid_request_object}

      _none ->
        :ok
    end
  end

  # An absent claim is fine (the parameter validators handle requiredness); a
  # present one must be a JSON string.
  defp string_valued_claim?(claims, name) do
    case Map.get(claims, name, :__absent__) do
      :__absent__ -> true
      value -> is_binary(value)
    end
  end

  # RFC 7519 §4.1.5 not-before + RFC 9101 / FAPI Message Signing 2.0 §5.3.1
  # strict-JAR policy. Whenever `nbf` is present as a NumericDate it must not
  # be in the future (clock skew tolerated) - a not-yet-valid request object is
  # rejected even in lenient mode. `require_nbf: true` additionally demands that
  # `nbf` be present and a non-negative integer NumericDate; a missing or
  # malformed value (e.g. a string) fails. `max_nbf_age_seconds` bounds how
  # stale a present `nbf` may be. Defaults (no require, no age bound) leave the
  # lenient JAR/OIDC §6.1 behaviour intact apart from honouring a present `nbf`.
  defp check_nbf(claims, opts) do
    nbf = Map.get(claims, "nbf")

    cond do
      require_nbf?(opts) and not numericdate?(nbf) -> {:error, :not_yet_valid}
      nbf_in_future?(nbf, opts) -> {:error, :not_yet_valid}
      nbf_too_old?(nbf, opts) -> {:error, :not_yet_valid}
      true -> :ok
    end
  end

  defp require_nbf?(opts), do: Keyword.get(opts, :require_nbf, false) == true

  defp nbf_in_future?(nbf, opts) when is_integer(nbf), do: nbf > unix_now(opts) + @clock_skew_seconds

  defp nbf_in_future?(_nbf, _opts), do: false

  defp nbf_too_old?(nbf, opts) when is_integer(nbf) do
    case Keyword.get(opts, :max_nbf_age_seconds) do
      max when is_integer(max) and max > 0 -> nbf < unix_now(opts) - max
      _ -> false
    end
  end

  defp nbf_too_old?(_nbf, _opts), do: false

  # RFC 7519 §4.1.4 expiry + RFC 9101 / FAPI Message Signing 2.0 §5.3.1: under
  # `require_exp: true`, `exp` must be present and a non-negative integer
  # NumericDate (a missing or malformed value fails). `max_lifetime_seconds`
  # bounds `exp - nbf`; because the bound is meaningless without both anchors,
  # under that policy a missing or malformed `nbf`/`exp` is itself a failure
  # (it MUST be paired with `require_nbf: true`/`require_exp: true` in practice).
  # The basic "exp in the past" rejection lives in `check_expiry/2`. Defaults
  # (no require, no lifetime bound) are no-ops.
  defp check_lifetime(claims, opts) do
    exp = Map.get(claims, "exp")
    nbf = Map.get(claims, "nbf")

    cond do
      require_exp?(opts) and not numericdate?(exp) -> {:error, :expired}
      lifetime_exceeded?(exp, nbf, opts) -> {:error, :expired}
      true -> :ok
    end
  end

  defp require_exp?(opts), do: Keyword.get(opts, :require_exp, false) == true

  # When `max_lifetime_seconds` is set, the bound needs both NumericDate
  # anchors; a missing or malformed `nbf`/`exp` is itself a failure.
  defp lifetime_exceeded?(exp, nbf, opts) do
    case Keyword.get(opts, :max_lifetime_seconds) do
      max when is_integer(max) and max > 0 -> not within_lifetime?(exp, nbf, max)
      _ -> false
    end
  end

  defp within_lifetime?(exp, nbf, max) when is_integer(exp) and is_integer(nbf), do: exp <= nbf + max

  defp within_lifetime?(_exp, _nbf, _max), do: false

  # A JWT NumericDate (RFC 7519 §2): a non-negative integer count of seconds.
  defp numericdate?(value), do: is_integer(value) and value >= 0

  defp claims_to_params(claims) do
    claims
    |> Map.drop(~w(iss sub aud exp nbf iat jti))
    |> Enum.reduce(%{}, fn
      {key, value}, acc when is_binary(value) ->
        Map.put(acc, key, value)

      {key, value}, acc when is_boolean(value) or is_integer(value) ->
        Map.put(acc, key, to_string(value))

      # A list is space-joined ONLY when every element is a string (an array
      # `resource`/`scope` in a signed request object). A list carrying a
      # non-string element (`"scope": [{"x": 1}]`) is dropped, not joined:
      # `Enum.join/2` raises `Protocol.UndefinedError` on a map/list element, and
      # this reduce runs on a signature-VALID request object, so an unguarded
      # join let a registered client crash the authorization-request process.
      {key, value}, acc when is_list(value) ->
        if Enum.all?(value, &is_binary/1), do: Map.put(acc, key, Enum.join(value, " ")), else: acc

      {key, value}, acc when is_map(value) ->
        Map.put(acc, key, JSON.encode!(value))

      {_key, _value}, acc ->
        acc
    end)
  end

  defp unix_now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = dt -> DateTime.to_unix(dt)
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end

  defp check_crit(header) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, :unsupported_critical_header}
    end
  end

  defp check_supported_alg(%{"alg" => "none"}), do: {:error, :request_not_supported}
  defp check_supported_alg(_header), do: :ok

  # RFC 9101 / FAPI Message Signing 2.0 §5.3.1: a strict-JAR profile may pin
  # the JOSE header `typ` (e.g. "oauth-authz-req+jwt"). Default `nil` accepts
  # any `typ`, including its absence, preserving lenient JAR/OIDC §6.1.
  #
  # `typ` is a media type (RFC 7515 §4.1.9), and media types are case-INSENSITIVE
  # (RFC 2045 §5.1), so the comparison is case-insensitive: the FAPI conformance
  # suite signs request objects with a randomly-cased typ (e.g.
  # "OautH-auThZ-REQ+jWt") to exercise exactly this. A `nil` member of `accepted`
  # permits an absent `typ`.
  defp check_typ(_header, nil), do: :ok

  defp check_typ(header, accepted) when is_list(accepted) do
    if typ_accepted?(Map.get(header, "typ"), accepted),
      do: :ok,
      else: {:error, :invalid_typ}
  end

  defp typ_accepted?(nil, accepted), do: Enum.member?(accepted, nil)

  defp typ_accepted?(typ, accepted) when is_binary(typ) do
    norm = normalize_typ(typ)
    Enum.any?(accepted, fn a -> is_binary(a) and normalize_typ(a) == norm end)
  end

  defp typ_accepted?(_typ, _accepted), do: false

  # RFC 7515 §4.1.9 / RFC 7519 §5.1: `typ` is a media type, and per convention
  # the `application/` prefix MAY be omitted when producing/comparing it - so
  # `JWT` and `application/JWT` are the same type (case-insensitively). That
  # convention applies only to a bare subtype: dropping the prefix is valid when
  # what remains has no further `/` (e.g. `application/jwt` -> `jwt`), but NOT
  # for a value that still contains a slash (`application/text/example` is a
  # different, malformed type, not `text/example`). Normalize both sides that
  # way so an accepted `JWT` also accepts `application/jwt`, and a rejected
  # `oauth-authz-req+jwt` also rejects its `application/`-prefixed spelling,
  # without collapsing unrelated multi-slash values together.
  defp normalize_typ(typ) do
    case String.downcase(typ) do
      "application/" <> rest = full ->
        if String.contains?(rest, "/"), do: full, else: rest

      down ->
        down
    end
  end

  defp peek_header(jwt) do
    case JWS.peek_json(jwt, :protected) do
      {:ok, map} -> {:ok, map}
      {:error, _reason} -> {:error, :invalid_request_object}
    end
  end
end
