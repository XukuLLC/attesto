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
  `Attesto.AuthorizationCode.issue/3`, it rides through to this struct as
  provenance metadata. Public `Attesto.RefreshToken.issue/3` rejects that
  value and creates a fresh family. After the host successfully issues that
  refresh token, it should use
  `Attesto.AuthorizationCode.issue_refresh_and_finalize/6`, which captures the
  returned family ID so code-reuse detection can revoke the actual descendants
  (OAuth 2.0 Security BCP §4.13). That helper also requires the issued refresh
  context to retain this grant's subject and client and to narrow, never widen,
  its scope/resource authorization. `AuthorizationCode.finalize/3` is for
  no-refresh flows and records a nil family in its replay marker. `nil` when no
  provenance ID was supplied.

  Under RFC 9449 §5, public-client refresh tokens must be DPoP-bound while
  confidential-client refresh tokens must not be DPoP-bound. The host performs
  that client classification because core cannot know it. For a DPoP-bound
  grant, the composition helper accepts a refresh context with either a nil
  `dpop_jkt` (confidential refresh) or this grant's exact JKT (public refresh),
  and rejects a different JKT.
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
