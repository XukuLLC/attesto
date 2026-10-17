defmodule Attesto.CIBA.Record do
  @moduledoc false

  alias Attesto.CIBA.Request
  alias Attesto.{Claims, Record, Scope}

  @notification_token_pattern ~r/\A[A-Za-z0-9\-._~+\/]+=*\z/
  @notification_token_max_length 1024
  @statuses [:pending, :approved, :denied, :consumed]
  @canonical_data_keys [
    :acr_values,
    :binding_message,
    :client_id,
    :client_notification_token,
    :delivery_mode,
    :dpop_jkt,
    :resource,
    :scope,
    :subject
  ]
  @consume_bound_fields [
    :auth_req_id_hash,
    :data,
    :subject,
    :acr,
    :auth_time,
    :granted_scope,
    :granted_claims,
    :interval,
    :expires_at
  ]
  @poll_bound_fields [:auth_req_id_hash, :data, :interval, :expires_at]

  @spec valid?(map(), binary()) :: boolean()
  def valid?(
        %{
          auth_req_id_hash: record_hash,
          data:
            %{
              acr_values: acr_values,
              binding_message: binding_message,
              client_id: client_id,
              client_notification_token: client_notification_token,
              delivery_mode: delivery_mode,
              dpop_jkt: dpop_jkt,
              resource: resource,
              scope: scope,
              subject: requested_subject
            } = data,
          status: status,
          interval: interval,
          expires_at: expires_at
        } = record,
        expected_hash
      ) do
    record_hash == expected_hash and
      request_data?(acr_values, binding_message, client_id, client_notification_token, delivery_mode) and
      grant_data?(dpop_jkt, resource, scope, requested_subject) and
      Record.exact_keys?(data, @canonical_data_keys) and
      state?(status, interval, expires_at) and optional_fields?(record) and decision_fields?(record)
  end

  def valid?(_record, _expected_hash), do: false

  @spec request_for_issue?(Request.t(), integer()) :: boolean()
  def request_for_issue?(%Request{} = request, now) do
    request_data?(
      request.acr_values,
      request.binding_message,
      request.client_id,
      request.client_notification_token,
      request.delivery_mode
    ) and hint?(request.hint) and scope?(request.scope) and
      optional_display_text?(request.user_code) and requested_expiry?(request.requested_expiry) and
      signed_request_state?(request, now)
  end

  @spec resource_list?(term()) :: boolean()
  def resource_list?(value), do: non_empty_string_list?(value)

  @spec optional_jkt?(term()) :: boolean()
  defdelegate optional_jkt?(value), to: Record

  @spec optional_non_empty_binary?(term()) :: boolean()
  defdelegate optional_non_empty_binary?(value), to: Record

  @spec optional_scope_list?(term()) :: boolean()
  def optional_scope_list?(nil), do: true
  def optional_scope_list?(value), do: scope_list?(value)

  @spec poll_transition?(map(), map(), binary(), non_neg_integer()) :: boolean()
  def poll_transition?(trusted_record, polled_record, hash, now) do
    valid?(polled_record, hash) and Map.get(polled_record, :last_polled_at) == now and
      fields_match?(trusted_record, polled_record, @poll_bound_fields)
  end

  @spec consume_transition?(map(), map(), binary()) :: boolean()
  def consume_transition?(trusted_record, consumed_record, hash) do
    trusted_record.status == :approved and consumed_record.status == :consumed and
      valid?(consumed_record, hash) and fields_match?(trusted_record, consumed_record, @consume_bound_fields)
  end

  @spec approve_transition?(map(), map(), map(), binary()) :: boolean()
  def approve_transition?(trusted_record, approved_record, approval_fields, hash) do
    trusted_record.status == :pending and approved_record.status == :approved and
      valid?(approved_record, hash) and fields_match?(trusted_record, approved_record, @poll_bound_fields) and
      Enum.all?([:subject, :acr, :auth_time, :granted_scope, :granted_claims], fn field ->
        Map.get(approved_record, field) == Map.get(approval_fields, field)
      end)
  end

  @spec deny_transition?(map(), map(), binary()) :: boolean()
  def deny_transition?(trusted_record, denied_record, hash) do
    trusted_record.status == :pending and denied_record.status == :denied and
      valid?(denied_record, hash) and fields_match?(trusted_record, denied_record, @poll_bound_fields)
  end

  defp request_data?(acr_values, binding_message, client_id, notification_token, delivery_mode) do
    non_empty_string_list?(acr_values) and optional_display_text?(binding_message) and
      Record.non_empty_binary?(client_id) and notification_binding?(delivery_mode, notification_token)
  end

  defp notification_binding?(:poll, nil), do: true

  defp notification_binding?(mode, token) when mode in [:ping, :push],
    do:
      Record.non_empty_binary?(token) and byte_size(token) <= @notification_token_max_length and
        Regex.match?(@notification_token_pattern, token)

  defp notification_binding?(_mode, _token), do: false

  defp hint?({kind, value}) when kind in [:login_hint, :login_hint_token, :id_token_hint],
    do: Record.non_empty_binary?(value)

  defp hint?(_hint), do: false

  defp scope?(scope), do: Scope.valid_list?(scope, allow_empty?: false) and "openid" in scope

  defp optional_display_text?(nil), do: true

  defp optional_display_text?(value) when is_binary(value) and value != "",
    do: String.valid?(value) and not Regex.match?(~r/[\x00-\x1F\x7F]/u, value)

  defp optional_display_text?(_value), do: false

  defp requested_expiry?(nil), do: true
  defp requested_expiry?(value), do: is_integer(value) and value > 0

  defp signed_request_state?(%Request{signed?: false, request_jti: nil, request_exp: nil}, _now), do: true

  defp signed_request_state?(%Request{signed?: true, request_jti: jti, request_exp: request_exp}, now),
    do: Record.non_empty_binary?(jti) and is_integer(request_exp) and request_exp > now

  defp signed_request_state?(_request, _now), do: false

  defp grant_data?(dpop_jkt, resource, scope, requested_subject) do
    Record.optional_jkt?(dpop_jkt) and resource_list?(resource) and scope_list?(scope) and
      Record.non_empty_binary?(requested_subject)
  end

  defp state?(status, interval, expires_at) do
    status in @statuses and is_integer(interval) and interval >= 0 and is_integer(expires_at) and expires_at >= 0
  end

  defp optional_fields?(record) do
    Record.optional_field?(record, :subject, &Record.optional_binary?/1) and
      Record.optional_field?(record, :acr, &Record.optional_binary?/1) and
      Record.optional_field?(record, :auth_time, &Record.optional_non_negative_integer?/1) and
      Record.optional_field?(record, :granted_scope, &optional_scope_list?/1) and
      Record.optional_field?(record, :granted_claims, &optional_json_object?/1) and
      Record.optional_field?(record, :last_polled_at, &Record.optional_non_negative_integer?/1)
  end

  defp decision_fields?(%{status: status} = record) when status in [:approved, :consumed] do
    case record do
      %{
        subject: subject,
        acr: acr,
        auth_time: auth_time,
        granted_scope: granted_scope,
        granted_claims: granted_claims
      } ->
        subject == record.data.subject and Record.non_empty_binary?(subject) and
          decision_authentication?(acr, record.data.acr_values, auth_time, record.expires_at) and
          decision_grant?(granted_scope, record.data.scope, granted_claims)

      _missing_decision_fields ->
        false
    end
  end

  defp decision_fields?(_record), do: true

  defp decision_authentication?(acr, requested_acrs, auth_time, expires_at) do
    decision_acr?(acr, requested_acrs) and is_integer(auth_time) and auth_time >= 0 and auth_time <= expires_at
  end

  defp decision_grant?(granted_scope, requested_scope, granted_claims) do
    optional_scope_list?(granted_scope) and granted_scope?(granted_scope, requested_scope) and
      Claims.portable_json_object?(granted_claims)
  end

  defp decision_acr?(acr, [_requested | _]), do: Record.non_empty_binary?(acr)
  defp decision_acr?(acr, []), do: Record.optional_non_empty_binary?(acr)

  defp fields_match?(left, right, fields) do
    Enum.all?(fields, fn field -> Map.get(left, field) == Map.get(right, field) end)
  end

  defp non_empty_string_list?(value), do: is_list(value) and Enum.all?(value, &Record.non_empty_binary?/1)

  defp scope_list?(value), do: Scope.valid_list?(value)
  defp granted_scope?(nil, _requested), do: true
  defp granted_scope?(granted, requested), do: MapSet.subset?(MapSet.new(granted), MapSet.new(requested))
  defp optional_json_object?(nil), do: true
  defp optional_json_object?(value), do: Claims.portable_json_object?(value)
end
