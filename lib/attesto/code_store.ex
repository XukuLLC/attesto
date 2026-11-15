defmodule Attesto.CodeStore do
  @moduledoc """
  Required storage contract for authorization codes and their token linkage.

  `Attesto.AuthorizationCode` reads, compares the immutable grant
  bindings, then claims a live code atomically. Refused comparisons write
  nothing. Expiry is checked only for live codes. Stores retain the grant in every state: `:live` (unclaimed),
  `:claimed` (issuing tokens), and `:redeemed` (issuance finished).
  `read/1` returns these as named fields, never as an error or metadata flag.

  All callbacks are required. `validate!/1` refuses an incomplete store with
  the missing callback's name. There are no capability-dependent tiers.
  Stores implement transitions; core decides whether a presentation is a
  replay and whether to revoke a refresh family. `finish/2` reports concurrent
  revocation in its atomic transition. A persistent store may conservatively deny
  linked access tokens as soon as a flag is written, including through a shared
  marker understood by previous-release nodes.

  ## Immutable grant and retention

  `put/1` accepts `:code_hash`, `:expires_at` (unix seconds), and `:data`.
  Data contains exactly `:client_id`, `:redirect_uri`, `:code_challenge`,
  `:subject`, `:scope`, `:resource`, `:dpop_jkt`, `:family_id`, and `:claims`.
  PKCE uses S256 when a challenge is present. Host context belongs in the
  portable string-keyed claims object. These fields never change after insert;
  the authorization's family provenance is separate from the redemption family.

  A read adds `:state`, `:redemption`, and `:revoked`.
  Redemption is nil until finish, then contains `:family_id`, `:subject`, and
  `:replay_retain_until`. Claimed records remain for at least 300 seconds after
  claim, then may be deleted once the code and linked access token expire.
  A missing claim makes `finish/2` return `:error`; core revokes newly issued
  credentials and returns no tokens. Cleanup must never reopen a claimed code.

  Redeemed records remain through code and linked token expiry. Housekeeping
  with an authoritative bundled refresh table may retire a family record once
  its last unexpired member disappears. Otherwise retain through the recorded
  family deadline, indefinitely when no deadline is known.

  Every write is atomic against competing operations on the same code. SQL
  batches lock code rows before refresh families; lock refresh families in
  ascending family-id order and take each family's advisory lock before its
  rows. See `Attesto.RefreshStore`. Store transitions never call a refresh store.

  See the custom-store upgrade guide for the previous callback mapping.
  """

  @type code_hash :: String.t()
  @type redemption :: %{
          family_id: String.t() | nil,
          subject: String.t(),
          replay_retain_until: non_neg_integer() | nil
        }
  @type entry :: %{code_hash: code_hash(), data: map(), expires_at: integer()}
  @type snapshot :: %{
          code_hash: code_hash(),
          data: map(),
          expires_at: integer(),
          state: :live | :claimed | :redeemed,
          redemption: redemption() | nil,
          revoked: boolean()
        }

  @doc "Atomically insert a live code. Duplicate hashes raise; never replace a record."
  @callback put(entry()) :: :ok
  @doc "Read any state without writing. Absent records return `:error`."
  @callback read(code_hash()) :: {:ok, snapshot()} | :error
  @doc "Atomically change live to claimed. Any other state returns `:error` without writes."
  @callback claim(code_hash()) :: :ok | :error
  @doc "Atomically finish a claimed code, recording redemption and returning concurrent revocation."
  @callback finish(code_hash(), redemption()) :: {:ok, boolean()} | :error
  @doc "Atomically flag a claimed code's replay. Other states return `:error` without writes."
  @callback flag_replay(code_hash()) :: :ok | :error
  @doc """
  Atomically delete matching live codes and flag matching claimed grants revoked.
  Return the number deleted. Redeemed records are unchanged. Criteria are ANDed;
  invalid or empty criteria raise `ArgumentError`. See `Attesto.RevocationCriteria`.
  """
  @callback delete_unclaimed(Attesto.RevocationCriteria.criteria()) :: {:ok, non_neg_integer()}
  @doc "Atomically link one token to a claimed/redeemed code, preserving revocation. Invalid state raises."
  @callback record_access_token_for_code(code_hash(), String.t(), integer()) :: :ok
  @doc "Atomically revoke a code's token linkage, including later linkage; absent codes are a no-op."
  @callback revoke_access_token_for_code(code_hash()) :: :ok
  @doc "Atomically revoke token linkages for redeemed codes belonging to a refresh family."
  @callback revoke_family_access_tokens(String.t()) :: :ok
  @doc "Read whether an unexpired linked token is revoked. Never writes."
  @callback access_token_revoked?(String.t()) :: boolean()

  @doc "Validate a redemption record's required fields; malformed records raise without writes."
  @spec validate_redemption!(redemption()) :: :ok
  def validate_redemption!(%{family_id: family, subject: subject, replay_retain_until: deadline}) do
    valid =
      Attesto.Record.optional_non_empty_binary?(family) and Attesto.Record.non_empty_binary?(subject) and
        (is_nil(deadline) or (is_binary(family) and is_integer(deadline) and deadline >= 0))

    if valid, do: :ok, else: raise(ArgumentError, "invalid authorization-code redemption record")
  end

  def validate_redemption!(_record), do: raise(ArgumentError, "invalid authorization-code redemption record")

  @doc "Validate that a module implements every required callback; raise naming a missing callback."
  @spec validate!(module()) :: :ok
  def validate!(store) do
    Code.ensure_loaded!(store)

    for {name, arity} <- __MODULE__.behaviour_info(:callbacks) do
      if !function_exported?(store, name, arity) do
        raise ArgumentError, "#{inspect(store)} must implement Attesto.CodeStore.#{name}/#{arity}"
      end
    end

    :ok
  end
end
