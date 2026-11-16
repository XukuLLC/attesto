defmodule Attesto.Test.CodeStoreAgent do
  @moduledoc """
  Agent-backed authorization-code store fixture for a host's tests.

  Use this module to define a named, in-memory test double with the
  `Attesto.CodeStore` callbacks and helpers for inspecting captured grants.
  It is a lightweight fixture, not a production store or a reference for
  storage validation and retention. Use `Attesto.Test.CodeStoreContract` to
  test a host's store implementation instead.

      defmodule Host.CodeStoreFixture do
        use Attesto.Test.CodeStoreAgent
      end

  Start the generated module with `start_supervised!(Host.CodeStoreFixture)`
  in a synchronous ExUnit case, or call its `start_link/1` directly. It is
  registered under its module name. `reset/0` clears all entries, `count/0`
  returns their number, and `peek/1` hashes a raw code and returns its snapshot
  or `nil`. `entry/1` hashes a raw code and returns the internal fixture entry,
  raising `KeyError` when absent. No ExUnit code runs when Attesto compiles.
  """

  @doc "Define a named Agent code-store fixture and its inspection helpers."
  defmacro __using__(_opts) do
    definitions =
      for {name, arity} <- Attesto.CodeStore.behaviour_info(:callbacks) do
        args = Macro.generate_arguments(arity, __MODULE__)

        quote do
          @impl Attesto.CodeStore
          def unquote(name)(unquote_splicing(args)) do
            unquote(__MODULE__).call(__MODULE__, unquote(name), [unquote_splicing(args)])
          end
        end
      end

    quote do
      @behaviour Attesto.CodeStore

      use Agent

      def start_link(_opts \\ []), do: Agent.start_link(fn -> %{} end, name: __MODULE__)
      def reset, do: Agent.update(__MODULE__, fn _ -> %{} end)
      def count, do: Agent.get(__MODULE__, &map_size/1)

      def peek(code) do
        case read(Attesto.Secret.hash(code)) do
          {:ok, snapshot} -> snapshot
          :error -> nil
        end
      end

      def entry(code), do: Agent.get(__MODULE__, &Map.fetch!(&1, Attesto.Secret.hash(code)))
      unquote_splicing(definitions)
    end
  end

  @doc false
  def call(agent, operation, args) do
    Agent.get_and_update(agent, &transition(&1, operation, args))
  end

  defp transition(state, :put, [entry]) do
    snapshot = Map.merge(entry, %{state: :live, redemption: nil, revoked: false})
    {:ok, Map.put_new(state, entry.code_hash, %{snapshot: snapshot, token: nil, revoked: false})}
  end

  defp transition(state, :read, [hash]) do
    result =
      case state[hash] do
        nil -> :error
        entry -> {:ok, entry.snapshot}
      end

    {result, state}
  end

  defp transition(state, :claim, [hash]), do: update(state, hash, :live, &%{&1 | state: :claimed}, :ok)
  defp transition(state, :flag_replay, [hash]), do: update(state, hash, :claimed, &%{&1 | revoked: true}, :ok)

  defp transition(state, :finish, [hash, redemption]) do
    flags = if state[hash], do: state[hash].snapshot.revoked
    update(state, hash, :claimed, &%{&1 | state: :redeemed, redemption: redemption}, {:ok, flags})
  end

  defp transition(state, :delete_unclaimed, [criteria]) do
    criteria = Attesto.RevocationCriteria.new!(criteria)

    Enum.reduce(state, {{:ok, 0}, state}, fn {hash, entry}, {{:ok, count}, acc} ->
      if Attesto.RevocationCriteria.match?(criteria, entry.snapshot.data) do
        cut_off(acc, hash, entry.snapshot.state, count)
      else
        {{:ok, count}, acc}
      end
    end)
  end

  defp transition(state, :record_access_token_for_code, [hash, jti, expiry]),
    do: {:ok, put_in(state, [hash, :token], %{jti: jti, expires_at: expiry})}

  defp transition(state, :revoke_access_token_for_code, [hash]),
    do: {:ok, if(state[hash], do: put_in(state, [hash, :revoked], true), else: state)}

  defp transition(state, :revoke_family_access_tokens, [family]) do
    updated =
      Map.new(state, fn {hash, entry} ->
        if match?(%{state: :redeemed, redemption: %{family_id: ^family}}, entry.snapshot),
          do: {hash, %{entry | revoked: true}},
          else: {hash, entry}
      end)

    {:ok, updated}
  end

  defp transition(state, :access_token_revoked?, [jti]) do
    result =
      Enum.any?(state, fn
        {_, %{token: %{jti: ^jti, expires_at: expiry}, revoked: true}} -> expiry > System.system_time(:second)
        _ -> false
      end)

    {result, state}
  end

  defp cut_off(state, hash, :live, count), do: {{:ok, count + 1}, Map.delete(state, hash)}
  defp cut_off(state, hash, :claimed, count), do: {{:ok, count}, put_in(state, [hash, :snapshot, :revoked], true)}
  defp cut_off(state, _hash, :redeemed, count), do: {{:ok, count}, state}

  defp update(state, hash, phase, change, result) do
    case state[hash] do
      %{snapshot: %{state: ^phase} = snapshot} -> {result, put_in(state, [hash, :snapshot], change.(snapshot))}
      _ -> {:error, state}
    end
  end
end
