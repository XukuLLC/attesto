defmodule Attesto.CredentialOfferStore do
  @moduledoc """
  Storage seam for by-reference OID4VCI credential offers.

  An issuer stores a credential offer under an opaque id and gives the wallet
  a URI containing that id. The wallet retrieves the offer through `fetch/1`.
  Retrieval is non-consuming: the pre-authorized code inside the offer is the
  single-use gate for the issuance flow.
  """

  @type entry :: %{id: String.t(), offer: map(), expires_at: integer()}

  @doc "Persist a credential-offer record."
  @callback put(entry()) :: :ok

  @doc "Fetch a live offer without consuming it, or return `:error`."
  @callback fetch(id :: String.t()) :: {:ok, map()} | :error
end
