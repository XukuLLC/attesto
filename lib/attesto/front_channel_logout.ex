defmodule Attesto.FrontChannelLogout do
  @moduledoc """
  OpenID Connect Front-Channel Logout 1.0 — the OP-side logout-URI builder.

  Front-Channel Logout notifies Relying Parties through the End-User's browser:
  when a session ends at the OP, the OP renders a page embedding an
  `<iframe src="frontchannel_logout_uri">` for every RP in the session that
  registered a `frontchannel_logout_uri` (Front-Channel Logout 1.0 §3). Loading
  the URI causes the RP to clear its own login state.

  Like the rest of attesto core this module is pure: it computes the exact URI
  each iframe loads and never touches HTTP, a store, or a `Plug.Conn`. The
  host's end-session controller owns rendering the page and continuing the
  RP-Initiated Logout flow (post-logout redirect) afterwards.

  ## `iss` / `sid` query parameters (§2)

  The OP MAY add `iss` (its Issuer Identifier) and `sid` (the session
  identifier asserted in the session's ID Tokens) to the logout URI so the RP
  can validate the request against the ID Token it holds; **if either is
  included, both MUST be**. An RP that registered
  `frontchannel_logout_session_required: true` requires them.

  attesto includes both parameters whenever the session's `sid` is known
  (the OP advertises `frontchannel_logout_session_supported`, so it always
  identifies the session when it can), and neither when it is not — an
  `iss`-only or `sid`-only URI is never produced.
  """

  alias Attesto.Config

  @doc """
  Build the URI an OP logout page loads in an iframe for one Relying Party.

  `registered_uri` is the RP's registered `frontchannel_logout_uri`
  (Front-Channel Logout 1.0 §2); any query it already carries is preserved.
  When `sid` is a non-empty session identifier, `iss` (from `config.issuer`)
  and `sid` are appended as query parameters — both together, per §2's
  "if either is included, both MUST be". With no `sid`, the registered URI is
  returned unchanged.

      logout_uri(config, "https://rp.example/fc", "sess-1")
      #=> "https://rp.example/fc?iss=https%3A%2F%2Fop.example&sid=sess-1"
  """
  @spec logout_uri(Config.t(), String.t(), String.t() | nil) :: String.t()
  def logout_uri(%Config{} = config, registered_uri, sid) when is_binary(registered_uri) do
    case sid do
      value when is_binary(value) and value != "" ->
        append_query(registered_uri, [{"iss", config.issuer}, {"sid", value}])

      _ ->
        registered_uri
    end
  end

  # Append parameters to the URI's query component, preserving any query the RP
  # registered (mirrors the authorization endpoint's redirect handling).
  defp append_query(uri, params) do
    encoded = URI.encode_query(params)
    parsed = URI.parse(uri)

    new_query =
      case parsed.query do
        nil -> encoded
        existing -> existing <> "&" <> encoded
      end

    URI.to_string(%{parsed | query: new_query})
  end
end
