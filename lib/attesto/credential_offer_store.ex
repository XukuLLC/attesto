defmodule Attesto.CredentialOfferStore do
  @moduledoc """
  Storage seam for by-reference OID4VCI credential offers.

  An issuer stores a credential offer under an opaque id and gives the wallet
  a URI containing that id. The wallet retrieves the offer through `fetch/1`.
  Retrieval is non-consuming: the pre-authorized code inside the offer is the
  single-use gate for the issuance flow.

  ## The id is a capability — do not choose it yourself

  The offer endpoint is unauthenticated (the wallet dereferences the
  `credential_offer_uri` before it holds any token), and a pre-authorized offer
  embeds a redeemable `pre-authorized_code`. The id is the ONLY thing standing
  between an attacker and that code: a guessable id lets them enumerate the
  endpoint and redeem a victim's offer. Create offers through
  `Attesto.CredentialOffer.store_by_reference/3`, which generates a 256-bit
  CSPRNG id and calls `put/1` for you. Never call `put/1` with a self-chosen or
  low-entropy id.
  """

  @type entry :: %{id: String.t(), offer: map(), expires_at: integer()}

  @doc """
  Persist a credential-offer record.

  The `:id` MUST be an unguessable, high-entropy value. Use
  `Attesto.CredentialOffer.store_by_reference/3` rather than calling this
  directly — it generates the id so a weak one can't slip in.
  """
  @callback put(entry()) :: :ok

  @doc "Fetch a live offer without consuming it, or return `:error`."
  @callback fetch(id :: String.t()) :: {:ok, map()} | :error
end
