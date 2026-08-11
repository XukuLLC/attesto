defmodule Attesto.SdJwt do
  @moduledoc """
  Selective Disclosure for JWTs (SD-JWT), draft-ietf-oauth-selective-disclosure-jwt.

  An SD-JWT lets an issuer sign a set of claims where individual claims are
  *selectively disclosable*: the signed JWT carries only the SHA-256 digest of
  each hidden claim (in the `_sd` array, or as an array element `{"...": digest}`),
  and the cleartext claim travels separately as a **Disclosure**. The holder
  chooses which Disclosures to release when presenting the credential, so a
  verifier learns only the disclosed subset while the issuer's single signature
  still covers all of them.

  The wire form is a `~`-separated list:

      <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<optional Key Binding JWT>

  A **Disclosure** is `base64url(UTF-8(JSON(array)))` with no padding, where the
  array is `[salt, claim_name, claim_value]` for an object property or
  `[salt, value]` for an array element. Its **digest** is
  `base64url(SHA-256(ASCII(disclosure)))` — computed over the exact disclosure
  string, so interop does not depend on how any party serialises JSON.

  This module is the base SD-JWT mechanism. `Attesto.SdJwtVc` layers the
  IETF SD-JWT VC profile (`vct`, `cnf`, `vc+sd-jwt` typing) on top.

  ## What is implemented

    * `issue/2` — sign an SD-JWT making chosen **top-level** claims selectively
      disclosable. (Nested/recursive and array-element issuance is a planned
      extension; the wire format it would produce is already a superset this
      module can verify.)
    * `verify/3` — the full recursive processing model from the spec: verify the
      issuer signature, then resolve `_sd` digests and array `{"...": digest}`
      elements at every depth, rejecting a presentation whose Disclosures do not
      all reference a digest (spec §7.3) or whose digests collide.
    * `verify_key_binding/3` — verify a holder Key Binding JWT over a verified
      presentation (nonce/aud/`sd_hash`), for the OID4VP verifier path.

  Like the rest of attesto core this module is conn-free and fail-closed.
  """

  alias Attesto.{JWS, MapParams, NumericDate, Secret, SecureCompare, SigningAlg}

  @default_sd_alg "sha-256"
  @separator "~"
  # ≥128 bits of salt entropy (spec §5.2.1 RECOMMENDS 128 bits).
  @salt_bytes 16
  # Reserved keys that MUST NOT appear as a Disclosure claim name (spec §5.2.2),
  # nor be produced by resolving one.
  @reserved_claim_names ~w(_sd ...)

  # DoS ceiling on a presentation, enforced in `split/1` before any base64/JSON
  # decode work: an authenticated holder could otherwise pad the `~`-joined
  # wire form with unbounded segments, each decoded and hashed during
  # `index_disclosures/2`. 256 KiB is generous for any real presentation (an
  # Issuer-signed JWT, its Disclosures, and an optional KB-JWT are typically a
  # few KB); 1000 Disclosures is far beyond any real credential's claim count.
  @max_presentation_bytes 256 * 1_024
  @max_disclosures 1_000

  @typedoc "A parsed, verified SD-JWT presentation."
  @type verified :: %{
          claims: map(),
          key_binding_jwt: String.t() | nil,
          issuer_jwt: String.t(),
          # The presented Disclosure strings in wire order, retained so
          # `verify_key_binding/3` can recompute the `sd_hash` over exactly what
          # was presented.
          disclosures: [String.t()]
        }

  @type key_binding_input :: %{
          required(:key_binding_jwt) => String.t() | nil,
          required(:issuer_jwt) => String.t(),
          required(:disclosures) => [String.t()],
          optional(term()) => term()
        }

  @type verify_error ::
          :malformed
          | :invalid_signature
          | :unsupported_alg
          | :invalid_typ
          | :invalid_disclosure
          | :unused_disclosure
          | :duplicate_digest
          | :unsupported_sd_alg
          | :reserved_claim_name

  # ── Disclosures ────────────────────────────────────────────────────────────

  @doc "A fresh salt for a Disclosure: 128-bit CSPRNG value, base64url, no padding."
  @spec generate_salt() :: String.t()
  def generate_salt, do: Secret.generate(@salt_bytes)

  @doc """
  The Disclosure string for an object property (`[salt, name, value]`).

  `name` must be a string; `value` is any JSON-encodable term. Returns the
  base64url(no-pad) of the UTF-8 JSON array.
  """
  @spec object_disclosure(String.t(), String.t(), term()) :: String.t()
  def object_disclosure(salt, name, value) when is_binary(salt) and is_binary(name) do
    [salt, name, value] |> JSON.encode!() |> JWS.encode64()
  end

  @doc "The Disclosure string for an array element (`[salt, value]`)."
  @spec array_disclosure(String.t(), term()) :: String.t()
  def array_disclosure(salt, value) when is_binary(salt) do
    [salt, value] |> JSON.encode!() |> JWS.encode64()
  end

  @doc """
  The digest of a Disclosure under `sd_alg` (default `#{@default_sd_alg}`):
  `base64url(SHA-256(ASCII(disclosure)))`.
  """
  @spec digest(String.t(), String.t()) :: String.t()
  def digest(disclosure, sd_alg \\ @default_sd_alg) when is_binary(disclosure) do
    :crypto.hash(hash_algorithm(sd_alg), disclosure) |> JWS.encode64()
  end

  # ── Issuance ───────────────────────────────────────────────────────────────

  @doc """
  Issue an SD-JWT, making the chosen top-level claims selectively disclosable.

  `claims` is the full claim set. Options:

    * `:disclosable` - the list of top-level claim names to hide behind `_sd`
      digests (each becomes a Disclosure). Every other claim is signed in the
      clear. Defaults to `[]` (a plain, fully-visible JWT with an empty `_sd`).
    * `:pem` - the issuer signing key (PEM). REQUIRED.
    * `:alg` - the JWS algorithm; inferred from the key when omitted.
    * `:typ` - the JOSE `typ` header (e.g. `"vc+sd-jwt"`); omitted when nil.
    * `:kid` - the JOSE `kid` header; omitted when nil.
    * `:sd_alg` - the hashing algorithm name for `_sd_alg`. Default
      `#{@default_sd_alg}`.

  Returns the combined **Issuance** string (`<JWT>~<D1>~...~<DN>~`, trailing
  separator, no Key Binding JWT).
  """
  @spec issue(map(), keyword()) :: String.t()
  def issue(claims, opts) when is_map(claims) and is_list(opts) do
    pem = Keyword.fetch!(opts, :pem)
    sd_alg = Keyword.get(opts, :sd_alg, @default_sd_alg)
    disclosable = Keyword.get(opts, :disclosable, [])

    Enum.each(disclosable, fn name ->
      if name in @reserved_claim_names,
        do: raise(ArgumentError, "cannot make the reserved claim #{inspect(name)} selectively disclosable")
    end)

    {disclosures, digests} =
      disclosable
      |> Enum.filter(&Map.has_key?(claims, &1))
      |> Enum.map_reduce([], fn name, acc ->
        disclosure = object_disclosure(generate_salt(), to_string(name), Map.fetch!(claims, name))
        {disclosure, [digest(disclosure, sd_alg) | acc]}
      end)

    visible = Map.drop(claims, disclosable)

    payload =
      visible
      # Sort the digests: their order must not leak the claim order (spec §5.1).
      # Digests are hash outputs, so sorting is order-independent of the source.
      |> Map.put("_sd", Enum.sort(digests))
      |> Map.put("_sd_alg", sd_alg)

    header = build_header(opts)
    jwt = Attesto.JWS.sign_compact(pem, header, payload)

    Enum.join([jwt | disclosures] ++ [""], @separator)
  end

  # ── Verification ───────────────────────────────────────────────────────────

  @doc """
  Verify an SD-JWT presentation and reconstruct the disclosed claims.

  `combined` is the `~`-separated presentation. `jwks` is the issuer's JWK Set
  (`%{"keys" => [...]}`, a single JWK map, or a list) used to verify the
  Issuer-signed JWT. Options:

    * `:accepted_algs` - JWS algorithms accepted for the issuer signature.
      Defaults to `Attesto.SigningAlg.fapi_algs/0`.

  Returns `{:ok, %{claims:, key_binding_jwt:, issuer_jwt:}}` where `claims` is
  the payload with every `_sd`/array digest resolved from the presented
  Disclosures (and the `_sd`/`_sd_alg` machinery removed). The Key Binding JWT,
  if present, is returned UNVERIFIED (see `verify_key_binding/3`) - reconstructing
  claims and checking holder binding are separate steps. Rejects a presentation
  in which any Disclosure is unused (spec §7.3) or any digest is duplicated.
  """
  @spec verify(String.t(), map() | [map()] | list(), keyword()) ::
          {:ok, verified()} | {:error, verify_error()}
  def verify(combined, jwks, opts \\ []) when is_binary(combined) do
    with {:ok, issuer_jwt, disclosures, kb_jwt} <- split(combined),
         {:ok, payload} <- verify_issuer_signature(issuer_jwt, jwks, opts),
         {:ok, sd_alg} <- sd_alg(payload),
         {:ok, by_digest} <- index_disclosures(disclosures, sd_alg),
         {:ok, claims, used} <- resolve(payload, by_digest),
         :ok <- all_disclosures_used(by_digest, used) do
      {:ok,
       %{
         claims: claims,
         key_binding_jwt: kb_jwt,
         issuer_jwt: issuer_jwt,
         disclosures: disclosures
       }}
    end
  end

  @doc """
  Verify a holder Key Binding JWT (`kb+jwt`) over an already-verified
  presentation.

  `verified` is the map `verify/3` returned; `holder_jwk` is the key the issuer
  bound the credential to (the `cnf` key). Options:

    * `:nonce` - the expected `nonce` (REQUIRED).
    * `:audience` - the expected `aud` (REQUIRED) - this verifier's identifier.
    * `:now` / `:max_age_seconds` - freshness bounds on `iat` (default 300s).

  Verifies the KB-JWT signature under `holder_jwk`, its `typ` (`kb+jwt`), the
  `nonce`/`aud`, and that `sd_hash` equals `base64url(SHA-256(<Issuer JWT and
  presented Disclosures, `~`-joined, trailing `~`>))` (spec §4.3) - so the
  holder signed over exactly the presentation the verifier reconstructed claims
  from.
  """
  @spec verify_key_binding(key_binding_input(), map(), keyword()) :: :ok | {:error, atom()}
  def verify_key_binding(%{key_binding_jwt: nil}, _holder_jwk, _opts), do: {:error, :missing_key_binding}

  def verify_key_binding(%{} = verified, holder_jwk, opts) when is_map(holder_jwk) do
    with {:ok, header} <- peek_header(verified.key_binding_jwt),
         :ok <- check_crit(header, :invalid_key_binding),
         :ok <- check_kb_typ(header),
         {:ok, claims} <- verify_kb_signature(verified.key_binding_jwt, header, holder_jwk, opts),
         :ok <- check_kb_nonce(claims, opts),
         :ok <- check_kb_audience(claims, opts),
         :ok <- check_kb_iat(claims, opts) do
      check_kb_sd_hash(claims, verified)
    end
  end

  # ── Splitting the wire form ────────────────────────────────────────────────

  # `<JWT>~<D1>~...~<Dn>~<KB?>`. A trailing `~` (empty last element) means no
  # Key Binding JWT; a non-empty last element is the KB-JWT (three dot-separated
  # segments). Everything between the JWT and the last element is a Disclosure.
  defp split(combined) when byte_size(combined) > @max_presentation_bytes, do: {:error, :malformed}

  defp split(combined) do
    with {:ok, segments} <- bounded_segments(combined) do
      parse_segments(segments)
    end
  end

  # Cap the segment count before any base64/JSON decode work happens.
  defp bounded_segments(combined) do
    segments = String.split(combined, @separator)
    if length(segments) > @max_disclosures + 2, do: {:error, :malformed}, else: {:ok, segments}
  end

  defp parse_segments([issuer_jwt | rest]) when issuer_jwt != "" and rest != [] do
    {middle, [last]} = Enum.split(rest, length(rest) - 1)
    kb_jwt = if last != "", do: last

    cond do
      Enum.any?(middle, &(&1 == "")) -> {:error, :malformed}
      not is_nil(kb_jwt) and not jwt_shaped?(kb_jwt) -> {:error, :malformed}
      true -> {:ok, issuer_jwt, middle, kb_jwt}
    end
  end

  defp parse_segments(_segments), do: {:error, :malformed}

  defp jwt_shaped?(value), do: match?([_, _, _], String.split(value, "."))

  # ── Disclosure indexing ────────────────────────────────────────────────────

  # Map each presented Disclosure digest to its decoded array. A digest that
  # appears twice across the presented Disclosures is a rejection (a verifier
  # must not silently pick one).
  defp index_disclosures(disclosures, sd_alg) do
    Enum.reduce_while(disclosures, {:ok, %{}}, fn disclosure, {:ok, acc} ->
      index_one(disclosure, sd_alg, acc)
    end)
  end

  defp index_one(disclosure, sd_alg, acc) do
    case decode_disclosure(disclosure) do
      {:ok, decoded} -> record_digest(digest(disclosure, sd_alg), decoded, acc)
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp record_digest(d, decoded, acc) do
    if Map.has_key?(acc, d),
      do: {:halt, {:error, :duplicate_digest}},
      else: {:cont, {:ok, Map.put(acc, d, decoded)}}
  end

  defp decode_disclosure(disclosure) do
    with {:ok, bytes} <- Base.url_decode64(disclosure, padding: false),
         {:ok, decoded} <- JSON.decode(bytes),
         :ok <- valid_disclosure_shape(decoded) do
      {:ok, %{used?: false, value: decoded}}
    else
      _ -> {:error, :invalid_disclosure}
    end
  end

  # `[salt, name, value]` (object property) or `[salt, value]` (array element).
  defp valid_disclosure_shape([salt, name, _value]) when is_binary(salt) and is_binary(name) do
    if name in @reserved_claim_names, do: {:error, :reserved_claim_name}, else: :ok
  end

  defp valid_disclosure_shape([salt, _value]) when is_binary(salt), do: :ok
  defp valid_disclosure_shape(_), do: {:error, :invalid_disclosure}

  # ── Recursive resolution (spec §7.3 processing model) ──────────────────────

  # Walk the payload, resolving `_sd` digests (object properties) and
  # `{"...": digest}` array elements from the presented Disclosures. Returns the
  # cleartext claims and the set of digests actually consumed, so the caller can
  # reject a presentation carrying an unused Disclosure.
  defp resolve(payload, by_digest) do
    {value, used} = resolve_value(payload, by_digest, MapSet.new())
    {:ok, value, used}
  catch
    {:sd_error, reason} -> {:error, reason}
  end

  defp resolve_value(%{} = object, by_digest, used) do
    {sd_digests, rest} = Map.pop(object, "_sd", [])
    rest = Map.delete(rest, "_sd_alg")

    if !is_list(sd_digests), do: throw({:sd_error, :invalid_disclosure})

    # Resolve the hidden object properties named by `_sd`.
    {disclosed, used} =
      Enum.reduce(sd_digests, {%{}, used}, fn d, {acc, used} ->
        resolve_object_digest(d, by_digest, acc, used)
      end)

    # Recurse into every still-present (cleartext) member.
    {resolved_rest, used} =
      Enum.reduce(rest, {%{}, used}, fn {k, v}, {acc, used} ->
        if k in @reserved_claim_names, do: throw({:sd_error, :reserved_claim_name})
        {rv, used} = resolve_value(v, by_digest, used)
        {Map.put(acc, k, rv), used}
      end)

    merged = merge_disclosed(resolved_rest, disclosed)
    {merged, used}
  end

  defp resolve_value(list, by_digest, used) when is_list(list) do
    {resolved, used} =
      Enum.reduce(list, {[], used}, fn element, {acc, used} ->
        case element do
          %{"..." => d} when map_size(element) == 1 ->
            resolve_array_digest(d, by_digest, acc, used)

          other ->
            {rv, used} = resolve_value(other, by_digest, used)
            {[rv | acc], used}
        end
      end)

    {Enum.reverse(resolved), used}
  end

  defp resolve_value(scalar, _by_digest, used), do: {scalar, used}

  # A digest listed in `_sd` that we hold a Disclosure for: it MUST be an
  # object-property disclosure `[salt, name, value]`. Digests we do not hold are
  # simply not disclosed (omitted). A single digest MUST NOT be used twice.
  defp resolve_object_digest(d, by_digest, acc, used) do
    if not is_binary(d), do: throw({:sd_error, :invalid_disclosure})

    case Map.get(by_digest, d) do
      nil ->
        {acc, used}

      %{value: [_salt, name, value]} ->
        if MapSet.member?(used, d), do: throw({:sd_error, :duplicate_digest})
        if Map.has_key?(acc, name), do: throw({:sd_error, :duplicate_digest})
        {rv, used} = resolve_value(value, by_digest, MapSet.put(used, d))
        {Map.put(acc, name, rv), used}

      %{value: [_salt, _value]} ->
        # An array-element Disclosure referenced from `_sd` is malformed.
        throw({:sd_error, :invalid_disclosure})
    end
  end

  defp resolve_array_digest(d, by_digest, acc, used) do
    if not is_binary(d), do: throw({:sd_error, :invalid_disclosure})

    case Map.get(by_digest, d) do
      nil ->
        # An undisclosed array element is dropped entirely (spec §7.3).
        {acc, used}

      %{value: [_salt, value]} ->
        if MapSet.member?(used, d), do: throw({:sd_error, :duplicate_digest})
        {rv, used} = resolve_value(value, by_digest, MapSet.put(used, d))
        {[rv | acc], used}

      %{value: [_salt, _name, _value]} ->
        # An object-property Disclosure referenced from an array is malformed.
        throw({:sd_error, :invalid_disclosure})
    end
  end

  defp merge_disclosed(rest, disclosed) do
    Enum.reduce(disclosed, rest, fn {name, value}, acc ->
      if Map.has_key?(acc, name), do: throw({:sd_error, :duplicate_digest})
      Map.put(acc, name, value)
    end)
  end

  # Spec §7.3: after processing, every presented Disclosure MUST have been used.
  defp all_disclosures_used(by_digest, used) do
    if MapSet.size(used) == map_size(by_digest), do: :ok, else: {:error, :unused_disclosure}
  end

  # ── Issuer signature ───────────────────────────────────────────────────────

  defp verify_issuer_signature(jwt, jwks, opts) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.fapi_algs())

    with {:ok, header} <- peek_header(jwt),
         :ok <- check_crit(header, :malformed),
         :ok <- check_typ(header, Keyword.get(opts, :accepted_typ)),
         alg when is_binary(alg) <- Map.get(header, "alg", :missing),
         true <- alg in accepted do
      verify_against_keys(jwt, alg, keys(jwks))
    else
      false -> {:error, :unsupported_alg}
      :missing -> {:error, :unsupported_alg}
      {:error, _} = err -> err
    end
  end

  # Enforce the Issuer-signed JWT's `typ` header against a caller allowlist (e.g.
  # SD-JWT VC's `vc+sd-jwt`). No constraint when `:accepted_typ` is absent.
  defp check_typ(_header, nil), do: :ok

  defp check_typ(%{"typ" => typ}, accepted) when is_list(accepted) do
    if typ in accepted, do: :ok, else: {:error, :invalid_typ}
  end

  defp check_typ(_header, _accepted), do: {:error, :invalid_typ}

  defp check_crit(header, error) do
    case JWS.reject_unsupported_crit(header, supported: []) do
      :ok -> :ok
      {:error, :unsupported_crit} -> {:error, error}
    end
  end

  defp verify_against_keys(jwt, alg, keys) do
    candidates =
      JWS.verification_candidates(keys,
        alg: alg,
        malformed_key: :skip
      )

    JWS.verify_strict(jwt, candidates,
      terminal_error: :invalid_signature,
      malformed_result: :continue,
      malformed_error: :invalid_signature
    )
  end

  defp sd_alg(payload) do
    case Map.get(payload, "_sd_alg", @default_sd_alg) do
      alg when is_binary(alg) ->
        try do
          _ = hash_algorithm(alg)
          {:ok, alg}
        rescue
          ArgumentError -> {:error, :unsupported_sd_alg}
        end

      _ ->
        {:error, :unsupported_sd_alg}
    end
  end

  # ── Key Binding JWT ────────────────────────────────────────────────────────

  @kb_typ "kb+jwt"
  @default_kb_max_age 300

  defp check_kb_typ(%{"typ" => @kb_typ}), do: :ok
  defp check_kb_typ(_), do: {:error, :invalid_key_binding}

  defp verify_kb_signature(kb_jwt, header, holder_jwk, opts) do
    accepted = Keyword.get(opts, :accepted_algs, SigningAlg.allowed())
    alg = Map.get(header, "alg")

    if is_binary(alg) and alg in accepted and alg != "none" and SigningAlg.rsa_params_ok?(holder_jwk) do
      # `rsa_params_ok?` guards the holder key here because the KB-JWT candidate
      # is built directly (not through `JWS.map_candidate!`), so an oversized-
      # exponent holder `cnf.jwk` would otherwise reach a scheduler-pinning
      # modexp during KB-JWT verification (RSA DoS).
      jwk = JOSE.JWK.from_map(holder_jwk)

      JWS.verify_strict(kb_jwt, [{nil, alg, jwk}],
        terminal_error: :invalid_key_binding,
        malformed_result: :halt,
        malformed_error: :invalid_key_binding
      )
    else
      {:error, :invalid_key_binding}
    end
  rescue
    _ -> {:error, :invalid_key_binding}
  end

  defp check_kb_nonce(%{"nonce" => nonce}, opts) do
    expected = Keyword.fetch!(opts, :nonce)
    if is_binary(nonce) and SecureCompare.equal?(nonce, expected), do: :ok, else: {:error, :invalid_key_binding}
  end

  defp check_kb_nonce(_claims, _opts), do: {:error, :invalid_key_binding}

  defp check_kb_audience(%{"aud" => aud}, opts) do
    expected = Keyword.fetch!(opts, :audience)
    if aud == expected, do: :ok, else: {:error, :invalid_key_binding}
  end

  defp check_kb_audience(_claims, _opts), do: {:error, :invalid_key_binding}

  defp check_kb_iat(%{"iat" => iat}, opts) when is_integer(iat) do
    now = NumericDate.now(opts, invalid_override: :fallback)
    max_age = Keyword.get(opts, :max_age_seconds, @default_kb_max_age)
    # Reject a future-dated or too-old key binding.
    if NumericDate.fresh?(iat, now, future_skew: 60, max_age: max_age) == :ok,
      do: :ok,
      else: {:error, :invalid_key_binding}
  end

  defp check_kb_iat(_claims, _opts), do: {:error, :invalid_key_binding}

  # `sd_hash` binds the KB-JWT to the exact Issuer-JWT + presented Disclosures.
  defp check_kb_sd_hash(%{"sd_hash" => presented}, verified) when is_binary(presented) do
    expected = presentation_hash(verified)
    if SecureCompare.equal?(presented, expected), do: :ok, else: {:error, :invalid_key_binding}
  end

  defp check_kb_sd_hash(_claims, _verified), do: {:error, :invalid_key_binding}

  # base64url(SHA-256(<Issuer JWT>~<D1>~...~<Dn>~)) - the presentation as it
  # stood immediately before the KB-JWT, trailing separator included.
  defp presentation_hash(%{issuer_jwt: jwt, disclosures: disclosures}) do
    to_hash = Enum.join([jwt | disclosures] ++ [""], @separator)
    :crypto.hash(:sha256, to_hash) |> JWS.encode64()
  end

  # ── Shared helpers ─────────────────────────────────────────────────────────

  defp build_header(opts) do
    %{"alg" => header_alg(opts)}
    |> MapParams.put_optional("typ", Keyword.get(opts, :typ))
    |> MapParams.put_optional("kid", Keyword.get(opts, :kid))
    |> MapParams.put_optional("x5c", x5c_header(Keyword.get(opts, :x5c)))
  end

  # The issuer X.509 certificate chain (RFC 7515 §4.1.6), a non-empty list of
  # base64 (not base64url) DER certificate strings. HAIP requires it so the
  # verifier can bind the credential to a trusted issuer certificate.
  defp x5c_header([_ | _] = x5c), do: x5c
  defp x5c_header(_x5c), do: nil

  defp header_alg(opts) do
    case Keyword.get(opts, :alg) do
      alg when is_binary(alg) -> alg
      _ -> opts |> Keyword.fetch!(:pem) |> JOSE.JWK.from_pem() |> SigningAlg.infer()
    end
  end

  defp keys(%{"keys" => keys}) when is_list(keys), do: keys
  defp keys(list) when is_list(list), do: list
  defp keys(%{} = jwk), do: [jwk]

  defp peek_header(jwt) do
    case JWS.peek_json(jwt, :protected) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :malformed}
    end
  end

  defp hash_algorithm("sha-256"), do: :sha256
  defp hash_algorithm("sha-384"), do: :sha384
  defp hash_algorithm("sha-512"), do: :sha512
  defp hash_algorithm(other), do: raise(ArgumentError, "unsupported _sd_alg: #{inspect(other)}")
end
