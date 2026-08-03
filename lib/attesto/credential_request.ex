defmodule Attesto.CredentialRequest do
  @moduledoc """
  OID4VCI Credential Request (`draft-ietf-oauth-openid4vci` §8.2).

  Parse and validate the decoded JSON object a wallet posts to a credential
  endpoint. This module is pure and conn-free; proof verification and
  credential issuance are the caller's concern.
  """

  alias Attesto.MapParams

  @type selector :: {:configuration_id, String.t()} | {:credential_identifier, String.t()}
  @type proof :: {String.t(), term()}
  @type parsed :: %{
          required(:selector) => selector(),
          required(:proofs) => [proof()],
          required(:response_encryption) => map() | nil
        }

  @doc """
  Parse an OID4VCI Credential Request.

  Credential selectors are required, while proofs are optional at parse time.
  Single and batch proofs are returned as one flat list for uniform handling
  by the caller.
  """
  @spec parse(map()) :: {:ok, parsed()} | {:error, atom()}
  def parse(request) when is_map(request) do
    with {:ok, selector} <- parse_selector(request),
         {:ok, proofs} <- parse_proofs(request),
         {:ok, response_encryption} <- parse_response_encryption(request) do
      {:ok,
       %{
         selector: selector,
         proofs: proofs,
         response_encryption: response_encryption
       }}
    end
  end

  def parse(request) do
    raise ArgumentError,
          "Attesto.CredentialRequest.parse/1 expects a map; got #{inspect(request)}"
  end

  defp parse_selector(request) do
    configuration_id_present? = key_present?(request, :credential_configuration_id)
    credential_identifier_present? = key_present?(request, :credential_identifier)

    case {configuration_id_present?, credential_identifier_present?} do
      {true, true} ->
        {:error, :ambiguous_credential_selector}

      {false, false} ->
        {:error, :missing_credential_selector}

      {true, false} ->
        selector_value(request, :credential_configuration_id, :configuration_id)

      {false, true} ->
        selector_value(request, :credential_identifier, :credential_identifier)
    end
  end

  defp selector_value(request, key, selector_tag) do
    case MapParams.fetch(request, key) do
      value when is_binary(value) and value != "" -> {:ok, {selector_tag, value}}
      _value -> {:error, :invalid_credential_selector}
    end
  end

  defp parse_proofs(request) do
    proof_present? = key_present?(request, :proof)
    proofs_present? = key_present?(request, :proofs)

    case {proof_present?, proofs_present?} do
      {true, true} ->
        {:error, :ambiguous_proof}

      {false, false} ->
        {:ok, []}

      {true, false} ->
        parse_single_proof(MapParams.fetch(request, :proof))

      {false, true} ->
        parse_batch_proofs(MapParams.fetch(request, :proofs))
    end
  end

  defp parse_single_proof(proof) when is_map(proof) do
    with {:ok, proof_type} <- proof_type(MapParams.fetch(proof, :proof_type)) do
      parse_single_proof_value(proof_type, proof)
    end
  end

  defp parse_single_proof(_proof), do: {:error, :invalid_proof}

  defp parse_single_proof_value("jwt", proof) do
    case MapParams.fetch(proof, :jwt) do
      jwt when is_binary(jwt) and jwt != "" -> {:ok, [{"jwt", jwt}]}
      _value -> {:error, :invalid_jwt_proof}
    end
  end

  defp parse_single_proof_value(proof_type, proof), do: {:ok, [{proof_type, MapParams.string_keyed_map(proof)}]}

  defp parse_batch_proofs(proofs) when is_map(proofs) do
    case map_size(proofs) do
      0 -> {:error, :invalid_proofs}
      _size -> reduce_batch_proofs(proofs)
    end
  end

  defp parse_batch_proofs(_proofs), do: {:error, :invalid_proofs}

  defp reduce_batch_proofs(proofs) do
    proofs
    |> Map.to_list()
    |> Enum.sort_by(fn {proof_type, _values} -> proof_type_sort_key(proof_type) end)
    |> Enum.reduce_while({:ok, []}, &parse_batch_entry/2)
  end

  defp parse_batch_entry({proof_type, values}, {:ok, parsed}) do
    with {:ok, proof_type} <- proof_type(normalize_proof_type_key(proof_type)),
         {:ok, values} <- batch_proof_values(proof_type, values) do
      {:cont, {:ok, parsed ++ Enum.map(values, &{proof_type, &1})}}
    else
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp batch_proof_values(_proof_type, values) when not is_list(values), do: {:error, :invalid_proofs}

  defp batch_proof_values(_proof_type, []), do: {:error, :empty_proofs}

  defp batch_proof_values("jwt", values) do
    if Enum.all?(values, &(is_binary(&1) and &1 != "")) do
      {:ok, values}
    else
      {:error, :invalid_jwt_proof}
    end
  end

  defp batch_proof_values(_proof_type, values), do: {:ok, values}

  defp parse_response_encryption(request) do
    if key_present?(request, :credential_response_encryption) do
      normalize_response_encryption(MapParams.fetch(request, :credential_response_encryption))
    else
      {:ok, nil}
    end
  end

  defp normalize_response_encryption(value) when is_map(value) do
    jwk = MapParams.fetch(value, :jwk)
    alg = MapParams.fetch(value, :alg)
    enc = MapParams.fetch(value, :enc)

    if is_map(jwk) and non_empty_string?(alg) and non_empty_string?(enc) do
      {:ok,
       %{
         "jwk" => MapParams.string_keyed_map(jwk),
         "alg" => alg,
         "enc" => enc
       }}
    else
      {:error, :invalid_credential_response_encryption}
    end
  end

  defp normalize_response_encryption(_value), do: {:error, :invalid_credential_response_encryption}

  defp proof_type(value) when is_binary(value) and value != "", do: {:ok, value}
  defp proof_type(_value), do: {:error, :invalid_proof_type}

  defp normalize_proof_type_key(value) when is_atom(value), do: Atom.to_string(value)
  defp normalize_proof_type_key(value), do: value

  defp proof_type_sort_key(value) when is_atom(value), do: Atom.to_string(value)
  defp proof_type_sort_key(value), do: value

  defp non_empty_string?(value), do: is_binary(value) and value != ""

  defp key_present?(map, key), do: Map.has_key?(map, key) or Map.has_key?(map, Atom.to_string(key))
end
