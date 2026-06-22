defmodule Attesto.ResourceIndicator do
  @moduledoc """
  RFC 8707 Resource Indicators for OAuth 2.0 — the conn-free primitive.

  A `resource` request parameter scopes an issued access token to one or more
  protected resources by setting the token's `aud` claim to the requested
  resource identifier(s) (§2.2). Audience is the cryptographic, RFC-blessed
  confinement: a token minted for resource A is structurally invalid at a
  sibling resource B, even when both share a scope vocabulary.

  This module is the single place that turns the raw `resource` parameter into
  a validated, authorized set of audience identifiers. It does two things and
  no more (it never touches a `Plug.Conn`, a store, or a clock):

    * **`validate/1`** — RFC 8707 §2.1 syntax. The parameter is multi-valued
      (scalar or array); each value MUST be an absolute URI with no fragment.
      Returns the de-duplicated indicator list, `{:ok, []}` when none was
      requested, or `{:error, :invalid_target}` for any malformed value.

    * **`authorize/2`** — RFC 8707 §2.2 authorization. Every requested resource
      MUST be one this authorization server is willing to mint for (the caller
      composes the allowlist — typically the server's own audience plus any
      configured / per-client allow-listed resources). An unserved resource is
      rejected `:invalid_target`: the AS never issues a token for a resource it
      does not serve.

  `:invalid_target` is the RFC 8707 §2 / RFC 6749 §5.2 error code the framing
  layer renders; this module returns the bare atom so it stays transport-free.
  """

  @doc """
  Parse and syntactically validate the requested resource indicator(s).

  `nil` (the parameter absent) yields `{:ok, []}`. A scalar binary or an array
  of binaries yields the de-duplicated list (order preserved) when every value
  is a valid absolute-URI indicator, else `{:error, :invalid_target}`. A
  present-but-empty value (`resource=`, an empty array, a blank/non-binary
  entry) fails closed rather than being treated as absent.
  """
  @spec validate(term()) :: {:ok, [String.t()]} | {:error, :invalid_target}
  def validate(nil), do: {:ok, []}
  def validate(value) when is_binary(value), do: validate([value])

  def validate(values) when is_list(values) do
    cond do
      values == [] -> {:error, :invalid_target}
      Enum.any?(values, &(not (is_binary(&1) and &1 != ""))) -> {:error, :invalid_target}
      Enum.all?(values, &valid_indicator?/1) -> {:ok, Enum.uniq(values)}
      true -> {:error, :invalid_target}
    end
  end

  def validate(_other), do: {:error, :invalid_target}

  @doc """
  Authorize already-validated resource indicators against an allowlist.

  Every member of `resources` MUST appear in `allowed`. Returns the resources
  unchanged on success, or `{:error, :invalid_target}` if any is not served by
  this authorization server. An empty `resources` list (no indicator requested)
  is trivially authorized.
  """
  @spec authorize([String.t()], [String.t()]) :: {:ok, [String.t()]} | {:error, :invalid_target}
  def authorize(resources, allowed) when is_list(resources) and is_list(allowed) do
    if Enum.all?(resources, &(&1 in allowed)),
      do: {:ok, resources},
      else: {:error, :invalid_target}
  end

  @doc """
  Whether a single value is a syntactically valid RFC 8707 resource indicator:
  an absolute URI (a non-empty scheme plus a host or path) with no fragment
  (§2.1) and no malformed percent-encoding (RFC 3986 §2.1).
  """
  @spec valid_indicator?(term()) :: boolean()
  def valid_indicator?(value) when is_binary(value) do
    not invalid_percent_encoding?(value) and absolute_uri_no_fragment?(value)
  end

  def valid_indicator?(_value), do: false

  # RFC 3986 §2.1: a `%` is valid only as the lead of a `%HH` triplet. `URI.new/1`
  # still admits a bare/invalid `%`, so reject it explicitly before building the
  # URI (else `resource=https://api.example/%ZZ` could mint a malformed `aud`).
  defp invalid_percent_encoding?(value), do: Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, value)

  # RFC 8707 §2.1: a resource indicator is an absolute URI (any scheme) with no
  # fragment. `URI.new/1` (unlike `URI.parse/1`) rejects whitespace/controls.
  defp absolute_uri_no_fragment?(value) do
    case URI.new(value) do
      {:ok, %URI{scheme: scheme, fragment: nil} = uri} when is_binary(scheme) and scheme != "" ->
        is_binary(uri.host) or (is_binary(uri.path) and uri.path != "")

      _ ->
        false
    end
  end
end
