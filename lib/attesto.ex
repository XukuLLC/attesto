defmodule Attesto do
  @moduledoc """
  A vendor-neutral OAuth 2.0 / OIDC authorization-server and
  resource-server engine.

  Attesto implements the parts of OAuth/OIDC that are the same for every
  deployment and easy to get subtly wrong - JWT signing and verification
  with a trusted, key-bound algorithm and `kid`-based key selection,
  sender-constrained tokens via DPoP (RFC 9449) and mutual-TLS (RFC 8705),
  PKCE (RFC 7636), and the scope grant-form algebra. It deliberately does
  **not** implement your identity model, persistence, or authorization policy.

  ## The split

  The library is organised around one boundary: *protocol* versus
  *policy*.

    * **Protocol (here).** Pure, effect-free functions over bytes and
      claims. `Attesto.Token.mint/2` assembles and signs a claim set;
      `Attesto.Token.verify/3` validates one. `Attesto.DPoP.verify_proof/2`
      checks a proof. `Attesto.MTLS.compute_thumbprint/1` digests a
      certificate. None of these read a database, a process dictionary,
      or application config.

    * **Policy (your application).** Which scopes exist, who may hold
      them, how you persist refresh tokens and authorization codes, how
      you audit issuance, and where signing keys come from. You inject
      the small, well-typed pieces Attesto needs (a keystore, a scope
      catalog, the set of principal kinds) and wrap the pure token
      functions with your own effects.

  Keeping issuance pure is what lets one issuer and one verifier serve
  several principal kinds (a machine client, a human session) at once:
  the kinds differ only in a configured claim value, a `sub` prefix, and
  a per-kind required-claim schema, all of which Attesto cross-checks.

  ## Entry points

    * `Attesto.Config` - the immutable configuration a token operation
      runs against (issuer, audience, keystore, principal kinds,
      lifetime).
    * `Attesto.Token` - issue and verify access tokens.
    * `Attesto.DPoP` / `Attesto.MTLS` - sender-constraint verification.
    * `Attesto.Scope` - scope grant-form matching.
    * `Attesto.Keystore` - the signing/verification key behaviour.

  See the `README` for the supply/own breakdown and the module docs for
  the RFC-level detail behind each check.
  """
end
