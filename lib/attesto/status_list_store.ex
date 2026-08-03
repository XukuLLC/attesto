defmodule Attesto.StatusListStore do
  @moduledoc """
  Storage seam for issuer-managed Token Status Lists.

  Each status-list URI has its own monotonically allocated index space. Newly
  allocated indices default to status `0` (VALID), and callers can later update
  an allocated index before passing `statuses/1` to `Attesto.StatusList`.

  `Attesto.StatusListStore.ETS` is a ready single-node implementation. A
  multi-node deployment implements this behaviour over shared storage so every
  issuer node allocates from the same index space.
  """

  @doc "Reserve and return the next status-list index for `uri`."
  @callback allocate(uri :: String.t()) :: {:ok, non_neg_integer()} | {:error, term()}

  @doc "Set an allocated index's status, or return `:error` if it was not allocated."
  @callback set_status(
              uri :: String.t(),
              idx :: non_neg_integer(),
              status :: non_neg_integer()
            ) :: :ok | :error

  @doc "Return the dense status list for `uri`, ordered from index zero."
  @callback statuses(uri :: String.t()) :: [non_neg_integer()]

  @doc "Read an allocated index's current status."
  @callback get_status(uri :: String.t(), idx :: non_neg_integer()) ::
              {:ok, non_neg_integer()} | :error

  @optional_callbacks get_status: 2
end
