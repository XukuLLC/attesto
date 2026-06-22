defmodule Attesto.StepUp.Requirement do
  @moduledoc """
  A normalized RFC 9470 step-up authentication requirement for a protected route.

  Two independent dimensions, both optional but at least one required:

    * `:acr_values` - the set of Authentication Context Class References the
      presented token's `acr` claim must be one of (RFC 9470 §3 / OIDC Core
      §2). Empty means "no `acr` constraint".
    * `:max_age` - the maximum age, in seconds, of the end-user authentication
      event: the token's `auth_time` must be no older than `now - max_age`.
      `nil` means "no freshness constraint".
  """

  defstruct acr_values: [], max_age: nil

  @type t :: %__MODULE__{acr_values: [String.t()], max_age: non_neg_integer() | nil}

  @doc """
  Build and validate a requirement from a `%Requirement{}` or a keyword list
  (`acr_values:` and/or `max_age:`).

  Fail-closed at configuration time: a malformed `:acr_values` / `:max_age`, or a
  requirement that constrains neither dimension, raises `ArgumentError` so a
  misconfigured route is caught at boot rather than silently never challenging.
  """
  @spec parse(t() | keyword()) :: t()
  def parse(%__MODULE__{} = req), do: validate!(req)

  def parse(opts) when is_list(opts) do
    validate!(%__MODULE__{
      acr_values: opts |> Keyword.get(:acr_values, []) |> List.wrap(),
      max_age: Keyword.get(opts, :max_age)
    })
  end

  defp validate!(%__MODULE__{acr_values: acrs, max_age: max_age} = req) do
    unless is_list(acrs) and Enum.all?(acrs, &valid_acr?/1) do
      raise ArgumentError,
            "step-up :acr_values must be a list of non-empty acr token strings (no whitespace, quotes, commas, or backslashes), got: #{inspect(acrs)}"
    end

    unless is_nil(max_age) or (is_integer(max_age) and max_age >= 0) do
      raise ArgumentError, "step-up :max_age must be a non-negative integer or nil, got: #{inspect(max_age)}"
    end

    if acrs == [] and is_nil(max_age) do
      raise ArgumentError, "step-up requirement must constrain :acr_values or :max_age (or both)"
    end

    req
  end

  # RFC 9470 §3: an `acr` value is echoed into a `WWW-Authenticate` quoted-string
  # challenge. `acr` is host-configured (trusted), but constraining it to a safe
  # token charset at config time forecloses any quote/param breakout regardless.
  defp valid_acr?(value) when is_binary(value) and value != "", do: not Regex.match?(~r/[\s",\\]/, value)
  defp valid_acr?(_value), do: false
end

defmodule Attesto.StepUp do
  @moduledoc """
  RFC 9470 Step-Up Authentication Challenge — the conn-free core primitive.

  A resource server that needs a fresher or stronger end-user authentication for
  a sensitive operation evaluates the presented (already verified) access token
  against an `Attesto.StepUp.Requirement` and, when it is not satisfied, answers
  RFC 9470 §3 `WWW-Authenticate: Bearer error="insufficient_user_authentication"`
  with the `acr_values` / `max_age` the client must re-request at the
  authorization endpoint.

  This module is conn-free: it reads only the token's `acr` / `auth_time` claims
  and a caller-supplied `now`, decides satisfaction (the framing layer renders
  the challenge), and never touches a `Plug.Conn`, a store, or a wall clock.

  ## Semantics

    * The two dimensions are a **conjunction** (RFC 9470 §4): the token must
      satisfy the `acr` set membership AND the `auth_time` freshness bound.
    * **Fail-closed**: a token whose `acr` is absent/non-string (when an
      `acr_values` set is required), or whose `auth_time` is absent/non-integer
      (when a `max_age` is required), does NOT satisfy the requirement. A token
      from a non-OIDC grant (no `auth_time`) therefore always challenges a
      freshness requirement — step-up routes are for end-user grants.
  """

  alias Attesto.StepUp.Requirement

  @error :insufficient_user_authentication

  @typedoc "The RFC 9470 §3 challenge parameters naming what the client must re-request."
  @type challenge :: %{optional(:acr_values) => String.t(), optional(:max_age) => non_neg_integer()}

  @doc """
  Evaluate verified token `claims` against `requirement` at `now` (unix seconds).

  Returns `:ok`, or `{:error, :insufficient_user_authentication, challenge}` where
  `challenge` carries the `acr_values` (space-delimited) / `max_age` the client
  must re-request.
  """
  @spec evaluate(Requirement.t(), map(), integer()) ::
          :ok | {:error, :insufficient_user_authentication, challenge()}
  def evaluate(%Requirement{} = requirement, claims, now) when is_map(claims) and is_integer(now) do
    if satisfied?(requirement, claims, now),
      do: :ok,
      else: {:error, @error, challenge_params(requirement)}
  end

  @doc """
  Whether the token's `acr` / `auth_time` claims satisfy `requirement` at `now`
  (the conjunction of both dimensions; fail-closed on absent/malformed claims).
  """
  @spec satisfied?(Requirement.t(), map(), integer()) :: boolean()
  def satisfied?(%Requirement{acr_values: acr_values, max_age: max_age}, claims, now)
      when is_map(claims) and is_integer(now) do
    acr_satisfied?(acr_values, claims) and auth_time_satisfied?(max_age, claims, now)
  end

  @doc """
  The RFC 9470 §3 challenge parameters for `requirement`: `:acr_values`
  (space-delimited) and/or `:max_age`. Transport-free — the plug owns the
  `WWW-Authenticate` scheme (Bearer vs DPoP) and quoting.
  """
  @spec challenge_params(Requirement.t()) :: challenge()
  def challenge_params(%Requirement{acr_values: acr_values, max_age: max_age}) do
    %{}
    |> maybe_put(:acr_values, if(acr_values != [], do: Enum.join(acr_values, " ")))
    |> maybe_put(:max_age, max_age)
  end

  # An empty accepted set imposes no `acr` constraint; otherwise the token's
  # `acr` MUST be a member. A missing/non-string `acr` fails closed.
  defp acr_satisfied?([], _claims), do: true

  defp acr_satisfied?(acr_values, claims) do
    case Map.get(claims, "acr") do
      acr when is_binary(acr) -> acr in acr_values
      _ -> false
    end
  end

  # `nil` max_age imposes no freshness constraint; otherwise `auth_time` MUST be
  # no older than `now - max_age`. A missing/non-integer `auth_time` fails closed
  # (RFC 9470 ties freshness to `auth_time`; there is no `iat` fallback).
  defp auth_time_satisfied?(nil, _claims, _now), do: true

  defp auth_time_satisfied?(max_age, claims, now) do
    case Map.get(claims, "auth_time") do
      auth_time when is_integer(auth_time) -> auth_time >= now - max_age
      _ -> false
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
