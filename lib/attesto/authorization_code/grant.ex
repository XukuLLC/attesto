defmodule Attesto.AuthorizationCode.Grant do
  @moduledoc """
  The validated context a successfully redeemed authorization code yields.

  `Attesto.AuthorizationCode.redeem/4` returns this struct once the code's
  expiry, redirect URI, PKCE verifier, and DPoP binding have all checked
  out. The host reads it to mint the access token (and, if it issues one,
  the refresh token): `subject` and `scope` become the token's `sub` and
  `scope`, `dpop_jkt` (when present) becomes the access token's `cnf.jkt`,
  and `claims` carries any host context that rode along from the
  authorization request.

  ## `family_id`

  When the authorization request supplied a `:family_id` to
  `Attesto.AuthorizationCode.issue/3`, it rides through to this struct so
  the host can mint the refresh-token family with that id. Linking the
  code to the family it spawns is what lets code-reuse detection revoke the
  right descendants (OAuth 2.0 Security BCP §4.13): a store that tracks
  reuse records this `family_id` at redemption and replays it if the code
  is presented again. `nil` when no family id was supplied.
  """

  @enforce_keys [:client_id, :redirect_uri, :subject]
  defstruct [:client_id, :redirect_uri, :subject, :dpop_jkt, :family_id, scope: [], resource: [], claims: %{}]

  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          subject: String.t(),
          scope: [String.t()],
          resource: [String.t()],
          dpop_jkt: String.t() | nil,
          family_id: String.t() | nil,
          claims: map()
        }

  @doc false
  @spec from_data(map()) :: t()
  def from_data(data) do
    %__MODULE__{
      client_id: data.client_id,
      redirect_uri: data.redirect_uri,
      subject: data.subject,
      scope: Map.get(data, :scope, []),
      resource: Map.get(data, :resource, []),
      dpop_jkt: Map.get(data, :dpop_jkt),
      family_id: Map.get(data, :family_id),
      claims: Map.get(data, :claims, %{})
    }
  end
end
