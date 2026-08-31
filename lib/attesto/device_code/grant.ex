defmodule Attesto.DeviceCode.Grant do
  @moduledoc """
  The validated context a successfully redeemed device code yields
  (RFC 8628 §3.4).

  `Attesto.DeviceCode.redeem/4` returns this once the device code's polling
  state machine reaches an approved, unexpired, single-use redemption. The host
  reads it to mint the access token (and, if it issues one, the refresh token):
  `subject` and `scope` become the token's `sub` and `scope`, `resource` (RFC
  8707) the `aud`, `dpop_jkt` (when present) the `cnf.jkt`, and `claims` carries
  the lossless, string-keyed I-JSON authentication/identity context the
  verification page recorded when the user approved. Persisted claim numbers
  are limited to exact-range integers; floats and unsupported VM terms are
  rejected.
  """

  @enforce_keys [:client_id, :subject]
  defstruct [:client_id, :subject, :dpop_jkt, scope: [], resource: [], claims: %{}]

  @type t :: %__MODULE__{
          client_id: String.t(),
          subject: String.t(),
          scope: [String.t()],
          resource: [String.t()],
          dpop_jkt: String.t() | nil,
          claims: map()
        }

  @doc false
  @spec from_record(map()) :: t()
  def from_record(record) when is_map(record) do
    data = Map.get(record, :data, %{})

    %__MODULE__{
      client_id: Map.get(data, :client_id),
      subject: Map.get(record, :subject),
      scope: Map.get(record, :granted_scope) || Map.get(data, :scope, []),
      resource: Map.get(data, :resource, []),
      dpop_jkt: Map.get(data, :dpop_jkt),
      claims: Map.get(record, :granted_claims, %{})
    }
  end
end
