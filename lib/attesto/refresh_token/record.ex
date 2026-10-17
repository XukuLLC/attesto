defmodule Attesto.RefreshToken.Record do
  @moduledoc false

  alias Attesto.{Claims, NumericDate, Record, Scope, Secret, Thumbprint}

  @max_issuer_bytes 2_048
  @issuer_claim_key "urn:attesto:refresh-token:issuer"
  @stored_context_keys [:acr, :auth_time, :claims, :client_id, :dpop_jkt, :resource, :scope, :subject]

  @spec build_issue(map(), keyword(), pos_integer()) :: {map(), map()}
  def build_issue(data, opts, default_ttl) when is_map(data) and is_list(opts) and is_integer(default_ttl) do
    token = Secret.generate()
    family_id = Keyword.get_lazy(opts, :family_id, fn -> Secret.generate(16) end)
    generation = Keyword.get(opts, :generation, 0)
    ttl = Keyword.get(opts, :ttl, default_ttl)

    record = %{
      token_hash: Secret.hash(token),
      family_id: family_id,
      generation: generation,
      data: data,
      expires_at: capped_expiry(data, NumericDate.now(opts) + ttl),
      consumed: false,
      consumed_at: nil,
      successor: nil
    }

    {%{token: token, family_id: family_id, generation: generation, expires_at: record.expires_at}, record}
  end

  @spec normalize_context(map()) :: {:ok, map()} | {:error, atom()}
  def normalize_context(context) when is_map(context) do
    scope = Map.get(context, :scope, [])
    resource = Map.get(context, :resource, [])
    dpop_jkt = Map.get(context, :dpop_jkt)

    with :ok <- validate_primary_context(context, scope, resource),
         :ok <- validate_supplemental_context(context, dpop_jkt) do
      {:ok, build_data(context, scope, resource, dpop_jkt)}
    end
  end

  @spec loaded?(term(), binary()) :: boolean()
  def loaded?(record, token_hash) do
    is_map(record) and Map.get(record, :token_hash) == token_hash and
      Record.non_empty_binary?(Map.get(record, :family_id)) and
      is_integer(Map.get(record, :generation)) and Map.get(record, :generation) >= 0 and
      valid_context?(Map.get(record, :data)) and is_integer(Map.get(record, :expires_at)) and
      valid_family_expiry?(record) and is_boolean(Map.get(record, :consumed))
  end

  @spec trusted_family_id(term(), binary()) :: binary() | nil
  def trusted_family_id(record, token_hash) when is_map(record) do
    if Map.get(record, :token_hash) == token_hash and Record.non_empty_binary?(Map.get(record, :family_id)),
      do: Map.get(record, :family_id)
  end

  def trusted_family_id(_record, _token_hash), do: nil

  @spec unconsumed?(map()) :: boolean()
  def unconsumed?(record) do
    is_nil(Map.get(record, :consumed_at)) and is_nil(Map.get(record, :successor))
  end

  @spec valid_claim?(map(), map()) :: boolean()
  def valid_claim?(claimed, original) do
    loaded?(claimed, original.token_hash) and Map.get(claimed, :consumed) == true and
      is_integer(Map.get(claimed, :consumed_at)) and same_identity?(claimed, original)
  end

  @spec same_identity?(map(), map()) :: boolean()
  def same_identity?(left, right) do
    Enum.all?([:token_hash, :family_id, :generation, :data, :expires_at], fn key ->
      Map.fetch(left, key) == Map.fetch(right, key)
    end)
  end

  @spec valid_context?(term()) :: boolean()
  def valid_context?(
        %{
          subject: subject,
          scope: scope,
          resource: resource,
          client_id: client_id,
          dpop_jkt: dpop_jkt,
          acr: acr,
          auth_time: auth_time,
          claims: claims
        } = context
      ) do
    exact_context_keys?(context) and valid_grant_context?(subject, scope, resource, client_id) and
      Record.optional_jkt?(dpop_jkt) and Claims.portable_json_object?(claims) and
      Record.optional_non_empty_binary?(acr) and Record.optional_non_negative_integer?(auth_time) and
      valid_stored_issuer?(claims) and valid_stored_attestation?(context) and valid_family_deadline?(context)
  end

  def valid_context?(_malformed), do: false

  @spec successor_context?(term(), map()) :: boolean()
  def successor_context?(context, parent) do
    valid_context?(context) and
      Enum.all?(
        [:subject, :client_id, :dpop_jkt, :attestation_jkt, :acr, :auth_time, :claims, :family_expires_at],
        fn key -> Map.fetch(context, key) == Map.fetch(parent, key) end
      ) and authorization_subset?(context.scope, parent.scope) and
      authorization_subset?(context.resource, parent.resource)
  end

  @spec issuer_matches?(term(), term()) :: boolean()
  def issuer_matches?(data, expected) when is_map(data) do
    with true <- valid_issuer?(expected),
         {:ok, claims} <- stored_claims(data),
         true <- is_map(claims),
         {:ok, stored} <- Map.fetch(claims, @issuer_claim_key),
         true <- valid_issuer?(stored) do
      stored == expected
    else
      _ -> false
    end
  end

  def issuer_matches?(_data, _expected), do: false

  @spec valid_issuer_binding?(term()) :: boolean()
  def valid_issuer_binding?(data) when is_map(data) do
    case stored_claims(data) do
      :absent -> true
      {:ok, claims} when is_map(claims) -> valid_stored_issuer?(claims)
      _invalid -> false
    end
  end

  def valid_issuer_binding?(_data), do: false

  @spec public_context(map()) :: map()
  def public_context(%{claims: claims} = context) do
    case Map.pop(claims, @issuer_claim_key) do
      {nil, public_claims} -> %{context | claims: public_claims}
      {issuer, public_claims} -> context |> Map.put(:claims, public_claims) |> Map.put(:issuer, issuer)
    end
  end

  defp valid_grant_context?(subject, scope, resource, client_id) do
    Record.non_empty_binary?(subject) and Scope.valid_list?(scope) and valid_resource?(resource) and
      Record.optional_non_empty_binary?(client_id)
  end

  defp exact_context_keys?(context) do
    keys = @stored_context_keys ++ Enum.filter([:family_expires_at, :attestation_jkt], &Map.has_key?(context, &1))
    Record.exact_keys?(context, keys)
  end

  defp valid_family_deadline?(context) do
    case Map.fetch(context, :family_expires_at) do
      :error -> true
      {:ok, deadline} -> is_integer(deadline) and deadline >= 0
    end
  end

  defp valid_family_expiry?(%{data: %{family_expires_at: deadline}, expires_at: expires_at}), do: expires_at <= deadline

  defp valid_family_expiry?(_record), do: true

  defp capped_expiry(%{family_expires_at: deadline}, expires_at), do: min(deadline, expires_at)
  defp capped_expiry(_data, expires_at), do: expires_at

  defp validate_primary_context(context, scope, resource) do
    cond do
      not Record.non_empty_binary?(Map.get(context, :subject)) -> {:error, :invalid_subject}
      not Scope.valid_list?(scope) -> {:error, :invalid_scope}
      not valid_resource?(resource) -> {:error, :invalid_resource}
      not Record.optional_non_empty_binary?(Map.get(context, :client_id)) -> {:error, :invalid_client_id}
      not valid_context_issuer?(context) -> {:error, :invalid_issuer}
      true -> :ok
    end
  end

  defp validate_supplemental_context(context, dpop_jkt) do
    cond do
      not Record.optional_jkt?(dpop_jkt) -> {:error, :invalid_dpop_jkt}
      not Record.optional_jkt?(Map.get(context, :attestation_jkt)) -> {:error, :invalid_attestation_jkt}
      not valid_host_claims?(Map.get(context, :claims, %{})) -> {:error, :invalid_claims}
      not Record.optional_non_empty_binary?(Map.get(context, :acr)) -> {:error, :invalid_acr}
      not Record.optional_non_negative_integer?(Map.get(context, :auth_time)) -> {:error, :invalid_auth_time}
      true -> :ok
    end
  end

  defp build_data(context, scope, resource, dpop_jkt) do
    %{
      subject: context.subject,
      scope: scope,
      resource: resource,
      client_id: Map.get(context, :client_id),
      dpop_jkt: dpop_jkt,
      acr: Map.get(context, :acr),
      auth_time: Map.get(context, :auth_time),
      claims: claims_with_issuer(context)
    }
    |> put_attestation_binding(Map.get(context, :attestation_jkt))
  end

  defp put_attestation_binding(data, nil), do: data
  defp put_attestation_binding(data, thumbprint), do: Map.put(data, :attestation_jkt, thumbprint)

  defp valid_stored_attestation?(context) do
    case Map.fetch(context, :attestation_jkt) do
      :error -> true
      {:ok, thumbprint} -> Thumbprint.valid?(thumbprint)
    end
  end

  defp valid_context_issuer?(context) do
    case Map.fetch(context, :issuer) do
      :error -> true
      {:ok, issuer} -> valid_issuer?(issuer)
    end
  end

  defp valid_host_claims?(claims) do
    Claims.portable_json_object?(claims) and not Map.has_key?(claims, @issuer_claim_key)
  end

  defp claims_with_issuer(context) do
    claims = Map.get(context, :claims, %{})

    case Map.fetch(context, :issuer) do
      :error -> claims
      {:ok, issuer} -> Map.put(claims, @issuer_claim_key, issuer)
    end
  end

  defp valid_stored_issuer?(claims) do
    case Map.fetch(claims, @issuer_claim_key) do
      :error -> true
      {:ok, issuer} -> valid_issuer?(issuer)
    end
  end

  defp stored_claims(data) do
    case {Map.fetch(data, :claims), Map.fetch(data, "claims")} do
      {:error, :error} -> :absent
      {{:ok, claims}, :error} -> {:ok, claims}
      {:error, {:ok, claims}} -> {:ok, claims}
      {{:ok, claims}, {:ok, claims}} -> {:ok, claims}
      {{:ok, _atom_claims}, {:ok, _string_claims}} -> :invalid
    end
  end

  defp valid_issuer?(issuer)
       when is_binary(issuer) and byte_size(issuer) > 0 and byte_size(issuer) <= @max_issuer_bytes do
    with true <- String.valid?(issuer),
         false <- String.match?(issuer, ~r/[\x00-\x20\x7F]/u),
         {:ok, uri} <- URI.new(issuer),
         true <- uri.scheme == "https",
         true <- is_binary(uri.host) and uri.host != "",
         true <- is_nil(uri.query) and is_nil(uri.fragment) do
      true
    else
      _ -> false
    end
  end

  defp valid_issuer?(_issuer), do: false

  defp valid_resource?(resource), do: is_list(resource) and Enum.all?(resource, &Record.non_empty_binary?/1)
  defp authorization_subset?(requested, granted), do: MapSet.subset?(MapSet.new(requested), MapSet.new(granted))
end
