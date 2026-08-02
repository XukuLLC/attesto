defmodule Attesto.Scope do
  @moduledoc """
  Scope grant-form matching for OAuth-style `<resource>.<action>` scopes.

  Attesto does not define *which* scopes exist - that catalog is your
  application's policy. It defines the *algebra*: given a catalog of
  concrete scope strings, what counts as a legal grant form, and whether
  a granted set covers a required scope. Build a catalog once with
  `new_catalog/1` and thread it through the matching functions.

  A scope is a dotted string of the form `<resource>.<action>`
  (e.g. `trackers.read`).

  ## Grant forms

  A *granted* scope (one stored on a credential, or carried in a JWT's
  `scope` claim) may be:

    * a concrete catalog entry such as `trackers.read`;
    * the resource-level wildcard `<resource>.*` (e.g. `webhooks.*`),
      which grants every catalog action under that resource;
    * the full wildcard `*`, which grants every catalog scope. Reserved
      for system-issued credentials; customer-facing issuance must not
      surface or accept it.

  Two validators encode this asymmetry:

    * `valid_grant_form?/2` accepts `*` and is the right check for
      system-issued credentials.
    * `customer_grant_form?/2` rejects `*` and is the check a public
      token endpoint or credential changeset must use.

  Wildcard grants are parsed strictly: only `<resource>.*` (exactly one
  dot, no other segments) is accepted. Deep forms like `trackers.read.*`
  are rejected so a grant is never silently broadened past a single
  resource.

  ## Required scopes

  A *required* scope (one a protected endpoint declares) MUST be a
  concrete catalog entry - passing a wildcard form as the requirement
  returns `false`, since a wildcard requirement would be ambiguous. Even
  a `*`-granted credential only authorizes catalog entries, so an
  uncatalogued endpoint requirement is never granted.

  `grants_all?/3` raises `ArgumentError` on a nil or empty required-scope
  list so a misconfigured authorization declaration (an endpoint that
  forgot to declare its required scope) fails loudly instead of silently
  authorizing every caller.

  ## Why strings, not atoms

  Scopes round-trip through HTTP requests, JWT claims, and database
  columns as strings; they are never coerced to atoms (a denial-of-service
  vector for externally-influenced values).
  """

  @full_wildcard "*"

  @enforce_keys [:entries, :resources]
  defstruct entries: MapSet.new(), resources: MapSet.new()

  @type t :: %__MODULE__{entries: MapSet.t(String.t()), resources: MapSet.t(String.t())}

  @doc """
  Build a catalog from the list of concrete scope strings your API
  understands. Computes the distinct resources (left-of-dot segments)
  once so per-request matching is allocation-light.
  """
  @spec new_catalog([String.t()]) :: t()
  def new_catalog(scopes) when is_list(scopes) do
    entries = MapSet.new(scopes)

    resources =
      scopes
      |> MapSet.new(&(&1 |> String.split(".", parts: 2) |> hd()))

    %__MODULE__{entries: entries, resources: resources}
  end

  @doc "The concrete scope strings in the catalog, sorted."
  @spec entries(t()) :: [String.t()]
  def entries(%__MODULE__{entries: entries}), do: entries |> MapSet.to_list() |> Enum.sort()

  @doc "The distinct resources present in the catalog, sorted."
  @spec resources(t()) :: [String.t()]
  def resources(%__MODULE__{resources: resources}), do: resources |> MapSet.to_list() |> Enum.sort()

  # RFC 6749 Appendix A scope-token ABNF: `1*NQCHAR`, where NQCHAR is
  # %x21 / %x23-5B / %x5D-7E - i.e. printable ASCII excluding space,
  # double-quote, and backslash. A scope string is space-delimited, so a
  # single token MUST NOT itself contain whitespace (or control characters
  # that could be misread downstream).
  @scope_token ~r/\A[\x21\x23-\x5B\x5D-\x7E]+\z/

  @doc """
  Returns `true` iff `value` is a syntactically-valid RFC 6749
  scope-token: a non-empty string of printable ASCII excluding space,
  double-quote, and backslash. This is a *wire-format* check independent
  of any catalog: it rejects a value like `"documents.read positions.read"`
  that, embedded in a space-delimited `scope` claim, would be
  indistinguishable from two separate grants.
  """
  @spec valid_token?(term()) :: boolean()
  def valid_token?(value) when is_binary(value), do: Regex.match?(@scope_token, value)
  def valid_token?(_), do: false

  @doc """
  Returns `true` iff `scope` is a concrete catalog entry (no wildcards).
  """
  @spec known?(t(), term()) :: boolean()
  def known?(%__MODULE__{entries: entries}, scope) when is_binary(scope), do: MapSet.member?(entries, scope)

  def known?(%__MODULE__{}, _), do: false

  @doc """
  Returns `true` iff `scope` is a legal granted form for a
  **system-issued** credential: a concrete catalog entry, the full
  wildcard `*`, or a resource-level wildcard `<resource>.*` whose
  resource appears in the catalog.

  Customer-facing surfaces MUST use `customer_grant_form?/2` instead - it
  rejects the system-only `*` form.
  """
  @spec valid_grant_form?(t(), term()) :: boolean()
  def valid_grant_form?(%__MODULE__{}, @full_wildcard), do: true
  def valid_grant_form?(%__MODULE__{} = catalog, scope), do: customer_grant_form?(catalog, scope)

  @doc """
  Returns `true` iff `scope` is a legal granted form for a
  **customer-facing** credential: a concrete catalog entry or a
  resource-level wildcard `<resource>.*` whose resource appears in the
  catalog. The full wildcard `*` is rejected.
  """
  @spec customer_grant_form?(t(), term()) :: boolean()
  def customer_grant_form?(%__MODULE__{}, @full_wildcard), do: false

  def customer_grant_form?(%__MODULE__{} = catalog, scope) when is_binary(scope) do
    known?(catalog, scope) or match?({:ok, _}, parse_resource_wildcard(catalog, scope))
  end

  def customer_grant_form?(%__MODULE__{}, _), do: false

  @doc """
  Returns `true` iff the `granted` scope list covers the `required`
  scope.

  `required` MUST be a concrete catalog entry; passing a wildcard form
  returns `false`. A nil or empty grant list returns `false`. Granted
  entries that are not valid grant forms are ignored - they cannot grant
  anything, even by accident. Even the full wildcard `*` only covers
  scopes actually in the catalog, so a typo or uncatalogued endpoint
  requirement is never authorized.
  """
  @spec grants?(t(), [String.t()] | nil, String.t()) :: boolean()
  def grants?(%__MODULE__{} = catalog, granted, required) when is_binary(required) do
    known?(catalog, required) and Enum.any?(List.wrap(granted), &covers?(catalog, &1, required))
  end

  def grants?(%__MODULE__{}, _, _), do: false

  @doc """
  Returns `true` iff `granted` covers every entry in `required`.

  Raises `ArgumentError` on a nil or empty `required` list so a
  misconfigured authorization declaration fails loudly instead of
  silently authorizing every caller.
  """
  @spec grants_all?(t(), [String.t()] | nil, [String.t(), ...]) :: boolean()
  def grants_all?(%__MODULE__{}, _granted, nil), do: raise_empty_required!("nil")
  def grants_all?(%__MODULE__{}, _granted, []), do: raise_empty_required!("[]")

  def grants_all?(%__MODULE__{} = catalog, granted, required) when is_list(required) do
    # Classify the granted set ONCE, then test each required scope against that
    # index in O(1). The naive form - `Enum.all?(required, &grants?(.., granted,
    # &1))` - rescans `granted` and re-`String.split`s a resource wildcard for
    # every (required, granted) pair, which is O(|required| x |granted|) with a
    # per-pair allocation. Since `required` is the caller-supplied requested
    # scope at a token endpoint, that made a large `scope` parameter a
    # denial-of-service lever (RFC 6749 §3.3 places no bound on the value). This
    # form is O(|granted| + |required|) and allocates once per side, so the same
    # 500k-token input that took ~20s is now flat. The result is identical to
    # the naive form (verified by property test): the index encodes exactly the
    # three ways `covers?/3` can hold.
    index = index_granted(catalog, granted)
    Enum.all?(required, &granted_by_index?(catalog, index, &1))
  end

  @doc """
  Returns the subset of `requested` scopes that are NOT valid
  customer-facing grant forms. Used at a token endpoint to surface
  `invalid_scope` (RFC 6749 §5.2) without leaking which scopes are
  catalogued. Rejects the system-only `*` form.
  """
  @spec unknown(t(), [String.t()] | nil) :: [String.t()]
  def unknown(%__MODULE__{}, nil), do: []

  def unknown(%__MODULE__{} = catalog, requested) when is_list(requested),
    do: Enum.reject(requested, &customer_grant_form?(catalog, &1))

  # ----- internal -----

  # Classify each granted scope once into the three shapes `covers?/3`
  # distinguishes: the full wildcard, a resource-level wildcard (`<r>.*` whose
  # resource is catalogued), or an exact scope. Non-binary entries are dropped,
  # matching `covers?/3`'s `false` fallthrough.
  defp index_granted(catalog, granted) do
    List.wrap(granted)
    |> Enum.reduce(%{full?: false, resources: MapSet.new(), exact: MapSet.new()}, fn
      scope, acc when is_binary(scope) ->
        if scope == @full_wildcard do
          %{acc | full?: true}
        else
          case parse_resource_wildcard(catalog, scope) do
            {:ok, resource} -> %{acc | resources: MapSet.put(acc.resources, resource)}
            :error -> %{acc | exact: MapSet.put(acc.exact, scope)}
          end
        end

      _scope, acc ->
        acc
    end)
  end

  # The index equivalent of `known?(required) and Enum.any?(granted, &covers?/3)`.
  # `known?` is factored to the front because every `covers?/3` branch requires
  # it; the disjunction then mirrors the three branches exactly.
  defp granted_by_index?(catalog, index, required) when is_binary(required) do
    known?(catalog, required) and
      (index.full? or
         MapSet.member?(index.exact, required) or
         MapSet.member?(index.resources, scope_resource(required)))
  end

  defp granted_by_index?(_catalog, _index, _required), do: false

  defp covers?(catalog, @full_wildcard, required), do: known?(catalog, required)

  defp covers?(catalog, granted, required) when is_binary(granted) and is_binary(required) do
    case parse_resource_wildcard(catalog, granted) do
      {:ok, resource} ->
        scope_resource(required) == resource and known?(catalog, required)

      :error ->
        granted == required and known?(catalog, required)
    end
  end

  defp covers?(_catalog, _, _), do: false

  # Parses a resource-level wildcard `<resource>.*` strictly: exactly two
  # segments, the second being `*` and the first a non-empty resource that
  # appears in the catalog. Rejects deep wildcards like `trackers.read.*`
  # and degenerate forms like `.*` / `*.read`.
  defp parse_resource_wildcard(%__MODULE__{resources: resources}, scope) when is_binary(scope) do
    case String.split(scope, ".") do
      [resource, "*"] when resource != "" ->
        if MapSet.member?(resources, resource), do: {:ok, resource}, else: :error

      _ ->
        :error
    end
  end

  defp parse_resource_wildcard(_catalog, _), do: :error

  defp scope_resource(scope) when is_binary(scope) do
    scope |> String.split(".", parts: 2) |> hd()
  end

  defp raise_empty_required!(label) do
    raise ArgumentError,
          "grants_all?/3 requires at least one required scope; got #{label}. " <>
            "Every authenticated endpoint must declare a scope."
  end
end
