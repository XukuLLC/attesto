defmodule Attesto.URI do
  @moduledoc """
  Shared URI validation for protocol identifiers received at trust boundaries.

  The validator rejects userinfo, fragments, hostless identifiers, whitespace,
  control characters, and malformed percent escapes before callers advertise
  or dereference a URL.
  """

  @doc """
  Returns whether `value` is an absolute HTTPS identifier.

  Set `:allow_http` to `true` only for a caller that deliberately supports an
  HTTP development endpoint. Every other structural check remains active.
  """
  @spec https_identifier?(term(), keyword()) :: boolean()
  def https_identifier?(value, opts \\ [])

  def https_identifier?(value, opts) when is_binary(value) and is_list(opts) do
    allow_http? = Keyword.get(opts, :allow_http, false)

    is_boolean(allow_http?) and value != "" and String.valid?(value) and
      valid_percent_encoding?(value) and
      valid_identifier?(value, allow_http?)
  end

  def https_identifier?(_value, _opts), do: false

  defp valid_identifier?(value, allow_http?) do
    with {:ok, %Elixir.URI{} = uri} <- Elixir.URI.new(value),
         true <- accepted_scheme?(uri.scheme, allow_http?),
         true <- is_binary(uri.host) and uri.host != "",
         true <- is_nil(uri.userinfo),
         true <- is_nil(uri.fragment) do
      true
    else
      _ -> false
    end
  rescue
    _exception -> false
  catch
    _kind, _reason -> false
  end

  defp accepted_scheme?("https", _allow_http?), do: true
  defp accepted_scheme?("http", true), do: true
  defp accepted_scheme?(_scheme, _allow_http?), do: false

  defp valid_percent_encoding?(value), do: not Regex.match?(~r/%(?![0-9A-Fa-f]{2})/, value)
end
