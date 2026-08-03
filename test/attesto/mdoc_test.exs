defmodule Attesto.MdocTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Attesto.Mdoc

  @doc_type "org.iso.18013.5.1.mDL"
  @mdl_namespace "org.iso.18013.5.1"
  @aamva_namespace "org.iso.18013.5.1.aamva"

  setup do
    {issuer_pem, issuer_public} = keypair()
    {_holder_pem, holder_public} = keypair()
    now = System.system_time(:second)

    opts =
      issue_opts(issuer_pem, holder_public, now,
        namespaces: %{
          @mdl_namespace => %{
            "age_over_21" => true,
            "birth_date" => "1990-01-02",
            "family_name" => "Doe",
            "given_name" => "Jane"
          },
          @aamva_namespace => %{"organ_donor" => false}
        }
      )

    %{holder_public: holder_public, issuer_pem: issuer_pem, issuer_public: issuer_public, now: now, opts: opts}
  end

  defp keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp issue_opts(issuer_pem, holder_public, now, overrides) do
    defaults = [
      device_key: holder_public,
      doc_type: @doc_type,
      issuer_pem: issuer_pem,
      namespaces: %{@mdl_namespace => %{"family_name" => "Doe"}},
      validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 3600}
    ]

    Keyword.merge(defaults, overrides)
  end

  defp decode!(encoded) do
    assert {:ok, value, ""} = CBOR.decode(encoded)
    value
  end

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}

  test "issue/1 and verify/3 recover every element and the holder key", ctx do
    assert {:ok, issued} = Mdoc.issue(ctx.opts)

    assert {:ok, verified} = Mdoc.verify(issued, ctx.issuer_public, now: ctx.now)
    assert verified.doc_type == @doc_type
    assert verified.device_key == ctx.holder_public
    assert verified.validity == Keyword.fetch!(ctx.opts, :validity)

    assert verified.namespaces == %{
             @mdl_namespace => %{
               "age_over_21" => true,
               "birth_date" => "1990-01-02",
               "family_name" => "Doe",
               "given_name" => "Jane"
             },
             @aamva_namespace => %{"organ_donor" => false}
           }
  end

  test "a changed element value fails item-digest verification", ctx do
    assert {:ok, issued} = Mdoc.issue(ctx.opts)
    raw = Base.url_decode64!(issued, padding: false)
    issuer_signed = decode!(raw)
    [first_item | remaining_items] = issuer_signed["nameSpaces"][@mdl_namespace]
    %CBOR.Tag{tag: 24, value: encoded_item_value} = first_item
    %CBOR.Tag{tag: :bytes, value: encoded_item} = encoded_item_value
    item = decode!(encoded_item)

    changed_item =
      %CBOR.Tag{
        tag: 24,
        value: bytes(CBOR.encode(Map.put(item, "elementValue", "tampered")))
      }

    tampered =
      put_in(
        issuer_signed,
        ["nameSpaces", @mdl_namespace],
        [changed_item | remaining_items]
      )

    assert {:error, :digest_mismatch} = Mdoc.verify(CBOR.encode(tampered), ctx.issuer_public, now: ctx.now)
  end

  test "expired and not-yet-valid documents are rejected", ctx do
    expired_opts =
      Keyword.put(ctx.opts, :validity, %{
        signed: ctx.now - 7200,
        valid_from: ctx.now - 7100,
        valid_until: ctx.now - 3600
      })

    future_opts =
      Keyword.put(ctx.opts, :validity, %{
        signed: ctx.now,
        valid_from: ctx.now + 3600,
        valid_until: ctx.now + 7200
      })

    assert {:ok, expired} = Mdoc.issue(expired_opts)
    assert {:ok, future} = Mdoc.issue(future_opts)
    assert {:error, :expired} = Mdoc.verify(expired, ctx.issuer_public, now: ctx.now)
    assert {:error, :not_yet_valid} = Mdoc.verify(future, ctx.issuer_public, now: ctx.now)
  end

  test "expected_doc_type rejects a different document type", ctx do
    assert {:ok, issued} = Mdoc.issue(ctx.opts)

    assert {:error, :unexpected_doc_type} =
             Mdoc.verify(issued, ctx.issuer_public,
               expected_doc_type: "eu.europa.ec.eudi.pid.1",
               now: ctx.now
             )
  end

  test "x5chain is carried in issuerAuth while supplied-key verification still succeeds", ctx do
    chain = [<<48, 3, 2, 1, 1>>, <<48, 3, 2, 1, 2>>]
    opts = Keyword.put(ctx.opts, :x5chain, chain)

    assert {:ok, issued} = Mdoc.issue(opts)
    assert {:ok, _verified} = Mdoc.verify(issued, ctx.issuer_public, now: ctx.now)

    issuer_signed = issued |> Base.url_decode64!(padding: false) |> decode!()
    [_protected, unprotected, _payload, _signature] = issuer_signed["issuerAuth"]

    assert Enum.map(unprotected[33], fn %CBOR.Tag{tag: :bytes, value: der} -> der end) == chain
  end
end
