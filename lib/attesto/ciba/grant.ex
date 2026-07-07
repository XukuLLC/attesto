defmodule Attesto.CIBA.Grant do
  @moduledoc """
  The validated context a successfully redeemed CIBA authentication request
  yields (CIBA Core §10.1).

  `Attesto.CIBA.redeem/4` returns this once the request's state machine
  reaches an approved, unexpired, single-use redemption. The host reads it to
  mint the token response through the same issuance path as its other grants:
  `subject` and `scope` become the tokens' `sub` and `scope`, `resource`
  (RFC 8707) the `aud`, `dpop_jkt` (when present) the `cnf.jkt`, and `acr` /
  `auth_time` the ID Token's authentication-context claims (CIBA Core §10.1:
  the ID Token is issued as for a normal OIDC token response; FAPI-CIBA
  §5.2.2 requires `acr` when the client requested one).
  """

  @enforce_keys [:client_id, :subject]
  defstruct [:acr, :auth_time, :client_id, :dpop_jkt, :subject, claims: %{}, resource: [], scope: []]

  @type t :: %__MODULE__{
          acr: String.t() | nil,
          auth_time: non_neg_integer() | nil,
          claims: map(),
          client_id: String.t(),
          dpop_jkt: String.t() | nil,
          resource: [String.t()],
          scope: [String.t()],
          subject: String.t()
        }

  @doc false
  @spec from_record(map()) :: t()
  def from_record(record) when is_map(record) do
    data = Map.get(record, :data, %{})

    %__MODULE__{
      acr: Map.get(record, :acr),
      auth_time: Map.get(record, :auth_time),
      claims: Map.get(record, :granted_claims) || %{},
      client_id: Map.get(data, :client_id),
      dpop_jkt: Map.get(data, :dpop_jkt),
      resource: Map.get(data, :resource, []),
      scope: Map.get(record, :granted_scope) || Map.get(data, :scope, []),
      subject: Map.get(record, :subject)
    }
  end
end
