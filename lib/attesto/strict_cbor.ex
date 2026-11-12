if Code.ensure_loaded?(CBOR) do
  defmodule Attesto.StrictCBOR do
    @moduledoc """
    Strict CBOR decoder with duplicate-map-key rejection and a nesting bound.

    RFC 8949 §5.6 leaves it to each protocol to say what a receiver does with a
    map that has the same key twice. COSE answers: "Labels in each of the maps
    MUST be unique. When processing messages, if a label appears multiple
    times, the message MUST be rejected as malformed" (RFC 9052 §3), and
    "Applications MUST NOT parse and process messages with the same label used
    twice as a key in a single map" (RFC 9052 §9).

    The general-purpose decoder builds an Elixir map as it goes, so a repeated
    key silently keeps one of its values and the duplicate is gone by the time
    a caller looks. This module walks the encoded bytes first and refuses the
    input when any map, at any depth, repeats a key. Two keys are the same when
    they decode to the same term, so a key written with a non-minimal or
    indefinite-length encoding is caught as well as a byte-for-byte repeat. The
    walk also refuses input nested deeper than `:max_depth`, which the
    general-purpose decoder, recursive per nesting level, does not bound.

    A byte string is opaque to the walk. CBOR carried inside one (a COSE
    protected header, a tag-24 embedded item) is checked when its bytes are
    decoded in turn, which every caller in this library does through this
    module.

    It is the CBOR counterpart of `Attesto.StrictJSON`, and the one decode
    boundary for COSE and mdoc input.
    """

    # A DeviceResponse nests about ten containers and a COSE_Sign1 four.
    @default_max_depth 32

    @doc """
    Decode exactly one CBOR data item from `bytes`.

    Returns `{:ok, value}` in the shape `CBOR.decode/1` gives, or
    `{:error, :invalid_cbor}` when the input is not a binary, is longer than
    `:max_bytes` (when given), is not well-formed, has bytes after the item,
    nests deeper than `:max_depth` (default `32`), or contains a map with a
    repeated key.
    """
    @spec decode(term(), keyword()) :: {:ok, term()} | {:error, :invalid_cbor}
    def decode(bytes, opts \\ [])

    def decode(bytes, opts) when is_binary(bytes) and is_list(opts) do
      max_depth = Keyword.get(opts, :max_depth, @default_max_depth)

      with true <- within_size?(bytes, Keyword.get(opts, :max_bytes)),
           {:ok, ""} <- item(bytes, max_depth),
           {:ok, value, ""} <- CBOR.decode(bytes) do
        {:ok, value}
      else
        _other -> {:error, :invalid_cbor}
      end
    rescue
      _error -> {:error, :invalid_cbor}
    catch
      _kind, _reason -> {:error, :invalid_cbor}
    end

    def decode(_bytes, _opts), do: {:error, :invalid_cbor}

    defp within_size?(_bytes, nil), do: true
    defp within_size?(bytes, max) when is_integer(max) and max > 0, do: byte_size(bytes) <= max

    # ── Structural walk (RFC 8949 §3) ───────────────────────────────────────
    #
    # `item/2` consumes one data item and returns the rest, building no terms
    # except the map keys it compares.

    defp item(_bytes, depth) when depth < 0, do: :error

    # Major types 0 and 1: unsigned and negative integers.
    defp item(<<major::3, info::5, rest::binary>>, _depth) when major in [0, 1] do
      with {:ok, _value, rest} <- argument(info, rest), do: {:ok, rest}
    end

    # Major types 2 and 3: byte and text strings, definite or chunked.
    defp item(<<major::3, 31::5, rest::binary>>, _depth) when major in [2, 3], do: chunks(rest, major)

    defp item(<<major::3, info::5, rest::binary>>, _depth) when major in [2, 3] do
      with {:ok, length, rest} <- argument(info, rest), do: skip(rest, length)
    end

    # Major type 4: arrays.
    defp item(<<4::3, 31::5, rest::binary>>, depth), do: items_until_break(rest, depth - 1)

    defp item(<<4::3, info::5, rest::binary>>, depth) do
      with {:ok, count, rest} <- argument(info, rest), do: items(rest, count, depth - 1)
    end

    # Major type 5: maps.
    defp item(<<5::3, 31::5, rest::binary>>, depth), do: pairs_until_break(rest, depth - 1, MapSet.new())

    defp item(<<5::3, info::5, rest::binary>>, depth) do
      with {:ok, count, rest} <- argument(info, rest), do: pairs(rest, count, depth - 1, MapSet.new())
    end

    # Major type 6: a tag and the one item it applies to.
    defp item(<<6::3, info::5, rest::binary>>, depth) do
      with {:ok, _tag, rest} <- argument(info, rest), do: item(rest, depth - 1)
    end

    # Major type 7: simple values and floats. A break outside an
    # indefinite-length container is not a data item.
    defp item(<<7::3, info::5, rest::binary>>, _depth) when info < 24, do: {:ok, rest}
    defp item(<<7::3, 24::5, _simple, rest::binary>>, _depth), do: {:ok, rest}
    defp item(<<7::3, 25::5, _float::binary-size(2), rest::binary>>, _depth), do: {:ok, rest}
    defp item(<<7::3, 26::5, _float::binary-size(4), rest::binary>>, _depth), do: {:ok, rest}
    defp item(<<7::3, 27::5, _float::binary-size(8), rest::binary>>, _depth), do: {:ok, rest}
    defp item(_bytes, _depth), do: :error

    defp argument(info, rest) when info < 24, do: {:ok, info, rest}
    defp argument(24, <<value::8, rest::binary>>), do: {:ok, value, rest}
    defp argument(25, <<value::16, rest::binary>>), do: {:ok, value, rest}
    defp argument(26, <<value::32, rest::binary>>), do: {:ok, value, rest}
    defp argument(27, <<value::64, rest::binary>>), do: {:ok, value, rest}
    defp argument(_info, _rest), do: :error

    defp skip(bytes, length) when byte_size(bytes) >= length do
      {:ok, binary_part(bytes, length, byte_size(bytes) - length)}
    end

    defp skip(_bytes, _length), do: :error

    # An indefinite-length string is a run of definite-length chunks of the
    # same major type, closed by a break.
    defp chunks(<<0xFF, rest::binary>>, _major), do: {:ok, rest}

    defp chunks(<<major::3, info::5, rest::binary>>, major) when info != 31 do
      with {:ok, length, rest} <- argument(info, rest),
           {:ok, rest} <- skip(rest, length) do
        chunks(rest, major)
      end
    end

    defp chunks(_bytes, _major), do: :error

    defp items(rest, 0, _depth), do: {:ok, rest}

    defp items(bytes, count, depth) do
      with {:ok, rest} <- item(bytes, depth), do: items(rest, count - 1, depth)
    end

    defp items_until_break(<<0xFF, rest::binary>>, _depth), do: {:ok, rest}

    defp items_until_break(bytes, depth) do
      with {:ok, rest} <- item(bytes, depth), do: items_until_break(rest, depth)
    end

    defp pairs(rest, 0, _depth, _seen), do: {:ok, rest}

    defp pairs(bytes, count, depth, seen) do
      with {:ok, rest, seen} <- pair(bytes, depth, seen), do: pairs(rest, count - 1, depth, seen)
    end

    defp pairs_until_break(<<0xFF, rest::binary>>, _depth, _seen), do: {:ok, rest}

    defp pairs_until_break(bytes, depth, seen) do
      with {:ok, rest, seen} <- pair(bytes, depth, seen), do: pairs_until_break(rest, depth, seen)
    end

    # One map entry. The key's encoded bytes are decoded on their own so two
    # encodings of one value compare equal, exactly as they would collide in
    # the map the general-purpose decoder builds.
    defp pair(bytes, depth, seen) do
      with {:ok, after_key} <- item(bytes, depth),
           key_bytes = binary_part(bytes, 0, byte_size(bytes) - byte_size(after_key)),
           {:ok, key, ""} <- CBOR.decode(key_bytes),
           false <- MapSet.member?(seen, key),
           {:ok, rest} <- item(after_key, depth) do
        {:ok, rest, MapSet.put(seen, key)}
      else
        _other -> :error
      end
    end
  end
else
  defmodule Attesto.StrictCBOR do
    @moduledoc "Requires the optional `:cbor` dependency."

    @dep_error "Attesto.StrictCBOR requires the optional :cbor dependency. " <>
                 "Add {:cbor, \"~> 1.0\"} to your deps."

    @doc false
    def decode(_bytes, _opts \\ []), do: raise(@dep_error)
  end
end
