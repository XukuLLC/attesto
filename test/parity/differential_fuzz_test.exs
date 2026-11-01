defmodule Attesto.Parity.DifferentialFuzzTest do
  @moduledoc """
  Differential fuzzing suite (`@moduletag :fuzz`) comparing Attesto's five core
  verification boundaries against independent reference implementations in
  Python (`joserfc` + `cryptography`) and Node.js (`panva/jose`, `@sd-jwt/core`,
  and `@auth0/mdl`).

  Excluded from the default `mix test` run in `test/test_helper.exs`; run with:

      mix test --only fuzz --seed 20261101
      mix test --only fuzz
  """

  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Attesto.{Cose, DPoP, JWE, JWS, Mdoc, SdJwt}
  alias Attesto.Test.{Factory, NodeBridge, PythonBridge}

  @moduletag :fuzz

  @fuzz_runs (case System.get_env("ATTESTO_FUZZ_RUNS") do
                nil -> 2_000
                val -> String.to_integer(val)
              end)

  @py_path Path.expand("../support/python", __DIR__)

  @jws_strict_rejections %{
    duplicate_header_key: {:error, :malformed},
    duplicate_payload_key: {:error, :invalid_signature},
    non_canonical_b64_payload: {:error, :malformed},
    non_canonical_b64_sig: {:error, :malformed},
    padded_b64_payload: {:error, :malformed},
    deep_json_payload: {:error, :invalid_signature},
    crit_empty: {:error, :unsupported_critical_header},
    rsa_jwk_without_explicit_ps256_alg: {:error, :invalid_signature},
    private_key_in_jwk: {:error, :invalid_signature},
    wrong_use_in_jwk: {:error, :invalid_signature}
  }

  @jwe_strict_rejections %{
    zip_def: {:error, :invalid_header},
    crit_in_header: {:error, :invalid_header},
    duplicate_header_key: {:error, :invalid_header},
    epk_with_private_d: {:error, :invalid_header},
    non_canonical_b64_tag: {:error, :invalid_jwe},
    non_canonical_apu: {:error, :invalid_header},
    non_base64_apu: {:error, :invalid_header}
  }

  @sd_jwt_strict_rejections %{
    reserved_claim_in_disclosure: {:error, :reserved_claim_name},
    nested_sd_alg: {:error, :reserved_claim_name},
    duplicate_disclosure: {:error, :duplicate_digest},
    non_string_salt_in_disclosure: {:error, :invalid_disclosure},
    non_string_name_in_disclosure: {:error, :invalid_disclosure},
    array_disclosure_in_object_sd: {:error, :invalid_disclosure},
    object_disclosure_in_array_slot: {:error, :invalid_disclosure},
    missing_trailing_tilde: {:error, :malformed},
    non_canonical_b64_disclosure: {:error, :invalid_disclosure},
    duplicate_json_in_disclosure: {:error, :invalid_disclosure},
    deep_json_in_disclosure: {:error, :invalid_disclosure}
  }

  @mdoc_strict_rejections %{
    short_item_random: {:error, :invalid_mdoc},
    duplicate_element_identifier: {:error, :invalid_mdoc},
    missing_dr_version: {:error, :invalid_mdoc},
    wrong_dr_version: {:error, :invalid_mdoc}
  }

  @dpop_strict_rejections %{
    http_scheme_htu: {:error, :invalid_htu},
    dot_segment_htu: {:error, :invalid_htu},
    tab_in_htu: {:error, :invalid_htu},
    triple_slash_htu: {:error, :invalid_htu},
    oversize_jti: {:error, :invalid_jti},
    private_key_in_embedded_jwk: {:error, :invalid_jwk},
    wrong_use_in_embedded_jwk: {:error, :invalid_jwk},
    duplicate_claim_key: {:error, :invalid_proof},
    non_canonical_b64_payload: {:error, :invalid_proof},
    ath_non_string_without_token: {:error, :invalid_ath}
  }

  setup_all do
    NodeBridge.ensure_started!()
    PythonBridge.ensure_started!()

    ec_pem = Factory.ec_pem()
    ec_jwk = JOSE.JWK.from_pem(ec_pem)
    {_, ec_priv_map} = JOSE.JWK.to_map(ec_jwk)
    {_, ec_pub_map} = ec_jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

    ec2_pem = Factory.ec_pem()
    ec2_jwk = JOSE.JWK.from_pem(ec2_pem)
    {_, ec2_priv_map} = JOSE.JWK.to_map(ec2_jwk)
    {_, ec2_pub_map} = ec2_jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

    rsa_pem = Factory.rsa_pem()
    rsa_jwk = JOSE.JWK.from_pem(rsa_pem)
    {_, rsa_pub_map} = rsa_jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

    {:ok,
     keys: %{
       ec_pem: ec_pem,
       ec_priv_map: ec_priv_map,
       ec_pub_map: ec_pub_map,
       ec2_pem: ec2_pem,
       ec2_priv_map: ec2_priv_map,
       ec2_pub_map: ec2_pub_map,
       rsa_pem: rsa_pem,
       rsa_pub_map: rsa_pub_map
     }}
  end

  # ── Deterministic Minimized Counterexamples & Shrinking Verification ───────

  describe "minimized counterexamples from StreamData shrinking" do
    test "StreamData shrinks a JWS disagreement to minimal claims (sub: \"a\", n: 0)", %{keys: k} do
      seed = :rand.seed_s(:exsplus, {2026, 1101, 1})

      {:error, %{shrunk_failure: shrunk}} =
        StreamData.check_all(jws_generator(k), [initial_seed: seed, max_runs: @fuzz_runs], fn item ->
          att = verify_jws_attesto(item)
          py = py_eval("fuzz_verify_jws(jwt, jwk, algs)", %{"jwt" => item.jwt, "jwk" => item.jwk, "algs" => item.algs})
          js = js_call(:fuzzVerifyJws, [item.jwt, item.jwk, item.algs])

          if match?({:ok, _}, att) == (py["ok"] == true) and match?({:ok, _}, att) == (js["ok"] == true) do
            {:ok, item}
          else
            {:error, %{mutation: item.mutation, att: att, py: py, js: js}}
          end
        end)

      assert shrunk.mutation == :duplicate_header_key
      assert shrunk.att == {:error, :malformed}
      assert shrunk.py["ok"] == true
      assert shrunk.py["claims"] == %{"n" => 0, "sub" => "a"}
      assert shrunk.js["ok"] == true
      assert shrunk.js["claims"] == %{"n" => 0, "sub" => "a"}
    end

    test "captures and minimizes @auth0/mdl TypeError crashes on cert-less IssuerAuth and untagged DeviceNameSpaces",
         %{keys: k} do
      now = 1_700_000_000
      context = [client_id: "https://verifier.example", nonce: "aaaa", response_uri: "https://verifier.example/resp"]
      {:ok, st} = Mdoc.session_transcript(context)
      st_b64 = st |> CBOR.encode() |> JWS.encode64()

      # 1. Valid mDL DeviceResponse without x5chain certificate in IssuerAuth:
      #    Attesto verifies against trusted issuer JWK; @auth0/mdl Verifier.verifyData crashes with TypeError.
      {valid_dr_bytes, ^now} = build_mutated_mdoc(k, "org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "a", now, st, :valid)
      valid_dr_b64 = JWS.encode64(valid_dr_bytes)

      assert {:ok, [%{namespaces: %{"org.iso.18013.5.1" => %{"given_name" => "a"}}}]} =
               Mdoc.verify_device_response(valid_dr_bytes, context, k.ec_pub_map, now: now)

      raw_verifier_res = js_call(:fuzzVerifyMdocRawVerifier, [valid_dr_b64, true, st_b64])
      assert raw_verifier_res["ok"] == false
      assert raw_verifier_res["error"] == "TypeError"
      assert raw_verifier_res["message"] =~ "issuerName"

      # 2. Untagged deviceSigned.nameSpaces (plain CBOR map instead of Tag 24):
      #    Attesto returns {:error, :invalid_mdoc}; @auth0/mdl mdl.parse crashes with TypeError reading 'entries'.
      {untagged_dr_bytes, ^now} =
        build_mutated_mdoc(
          k,
          "org.iso.18013.5.1.mDL",
          "org.iso.18013.5.1",
          "a",
          now,
          st,
          :untagged_device_namespaces
        )

      assert {:error, :invalid_mdoc} =
               Mdoc.verify_device_response(untagged_dr_bytes, context, k.ec_pub_map, now: now)

      untagged_js_res =
        js_call(:fuzzVerifyMdocDeviceResponse, [
          JWS.encode64(untagged_dr_bytes),
          st_b64,
          k.ec_pub_map,
          %{"now" => now}
        ])

      assert untagged_js_res["ok"] == false
      assert untagged_js_res["error"] == "TypeError"
      assert untagged_js_res["message"] =~ "entries"
    end

    test "regression: DPoP, SD-JWT, and mdoc defects found by differential fuzzing are rejected", %{keys: k} do
      now = 1_700_000_000

      # 1. DPoP malformed / out-of-range ports in htu
      for bad_htu <- [
            "https://api.example.com:abc/a",
            "https://api.example.com:99999/a",
            "https://api.example.com:443xyz/a",
            "https://api.example.com:0/a",
            "https://api.example.com:/a"
          ] do
        proof =
          JWS.sign_compact(
            k.ec_pem,
            %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => k.ec_pub_map},
            %{"htm" => "POST", "htu" => bad_htu, "iat" => now, "jti" => "a"}
          )

        assert {:error, :invalid_htu} =
                 DPoP.verify_proof(proof, http_method: "POST", http_uri: "https://api.example.com/a", now: now)
      end

      # 2. SD-JWT padded base64url disclosure and duplicate JSON member in disclosure
      padded_d = "WyJzIiwiYSIsMV0="
      assert {:error, :invalid_disclosure} = SdJwt.decode_disclosures([padded_d], "sha-256")
      assert js_call(:fuzzDecodeDisclosures, [[padded_d], "sha-256"])["ok"] == false

      dup_d = JWS.encode64(~s(["s","profile",{"admin":true,"admin":false}]))
      assert {:error, :invalid_disclosure} = SdJwt.decode_disclosures([dup_d], "sha-256")

      dup_jwt =
        JWS.sign_compact(
          k.ec_pem,
          %{"alg" => "ES256", "typ" => "vc+sd-jwt"},
          %{"iss" => "https://issuer.example", "_sd_alg" => "sha-256", "_sd" => [SdJwt.digest(dup_d)]}
        )

      assert {:error, :invalid_disclosure} =
               SdJwt.verify(dup_jwt <> "~" <> dup_d <> "~", k.ec_pub_map, accepted_algs: ["ES256"])

      # 3. mdoc non-map DeviceSignedItems and missing/wrong DeviceResponse version
      context = [client_id: "https://verifier.example", nonce: "aaaa", response_uri: "https://verifier.example/resp"]
      {:ok, st} = Mdoc.session_transcript(context)
      st_b64 = st |> CBOR.encode() |> JWS.encode64()

      {bad_dev_ns_bytes, ^now} =
        build_mutated_mdoc(
          k,
          "org.iso.18013.5.1.mDL",
          "org.iso.18013.5.1",
          "a",
          now,
          st,
          :non_map_device_signed_items
        )

      assert {:error, :invalid_mdoc} =
               Mdoc.verify_device_response(bad_dev_ns_bytes, context, k.ec_pub_map, now: now)

      assert js_call(:fuzzVerifyMdocDeviceResponse, [
               JWS.encode64(bad_dev_ns_bytes),
               st_b64,
               k.ec_pub_map,
               %{"now" => now}
             ])["ok"] == false
    end
  end

  # ── Property 1: JWS Compact Verification ───────────────────────────────────

  property "JWS compact verification: Attesto never accepts what joserfc or jose rejects", %{keys: k} do
    check all(item <- jws_generator(k), max_runs: @fuzz_runs) do
      att_res = verify_jws_attesto(item)

      py_res =
        py_eval("fuzz_verify_jws(jwt, jwk, algs)", %{
          "jwt" => item.jwt,
          "jwk" => item.jwk,
          "algs" => item.algs
        })

      js_res = js_call(:fuzzVerifyJws, [item.jwt, item.jwk, item.algs])

      case att_res do
        {:ok, claims} ->
          assert item.mutation == :valid
          assert py_res["ok"] == true
          assert js_res["ok"] == true
          assert py_res["claims"] == claims
          assert js_res["claims"] == claims

        {:error, _reason} ->
          if py_res["ok"] == true or js_res["ok"] == true do
            assert Map.fetch(@jws_strict_rejections, item.mutation) == {:ok, att_res}
          else
            assert py_res["ok"] == false
            assert js_res["ok"] == false
          end
      end
    end
  end

  # ── Property 2: JWE Compact Decryption ─────────────────────────────────────

  property "JWE compact decryption (ECDH-ES P-256, A128GCM/A256GCM): Attesto never accepts what joserfc or jose rejects",
           %{keys: k} do
    check all(item <- jwe_generator(k), max_runs: @fuzz_runs) do
      att_res = JWE.decrypt(item.priv_jwk, item.compact)
      algs = ["ECDH-ES"]
      encs = ["A128GCM", "A256GCM"]

      py_res =
        py_eval("fuzz_decrypt_jwe(c, k, a, e)", %{
          "c" => item.compact,
          "k" => item.priv_jwk,
          "a" => algs,
          "e" => encs
        })

      js_res = js_call(:fuzzDecryptJwe, [item.compact, item.priv_jwk, algs, encs])

      case att_res do
        {:ok, plaintext, _header} ->
          assert item.mutation == :valid
          assert py_res["ok"] == true
          assert js_res["ok"] == true
          assert JWS.encode64(plaintext) == item.plaintext_b64
          assert py_res["plaintext_b64"] == item.plaintext_b64
          assert js_res["plaintext_b64"] == item.plaintext_b64

        {:error, _reason} ->
          if py_res["ok"] == true or js_res["ok"] == true do
            assert Map.fetch(@jwe_strict_rejections, item.mutation) == {:ok, att_res}
          else
            assert py_res["ok"] == false
            assert js_res["ok"] == false
          end
      end
    end
  end

  # ── Property 3: SD-JWT Verification & Disclosure Decoding ──────────────────

  property "SD-JWT verification and disclosure decoding: Attesto never accepts what @sd-jwt/core or Python rejects",
           %{keys: k} do
    check all(item <- sd_jwt_generator(k), max_runs: @fuzz_runs) do
      att_res = verify_sd_jwt_attesto(item)

      py_res =
        py_eval("fuzz_verify_sd_jwt(c, ij, algs, hj, kb)", %{
          "c" => item.combined,
          "ij" => item.issuer_jwk,
          "algs" => ["ES256"],
          "hj" => item.holder_jwk,
          "kb" => item.kb_opts
        })

      js_res =
        js_call(:fuzzVerifySdJwt, [
          item.combined,
          item.issuer_jwk,
          ["ES256"],
          item.holder_jwk,
          item.kb_opts
        ])

      case att_res do
        {:ok, claims} ->
          assert item.mutation in [:valid, :valid_with_kb]
          assert py_res["ok"] == true
          assert js_res["ok"] == true
          assert py_res["claims"] == claims
          assert js_res["claims"] == claims

        {:error, _reason} ->
          if py_res["ok"] == true or js_res["ok"] == true do
            assert Map.fetch(@sd_jwt_strict_rejections, item.mutation) == {:ok, att_res}
          else
            assert py_res["ok"] == false
            assert js_res["ok"] == false
          end
      end
    end
  end

  # ── Property 4: mdoc DeviceResponse Verification ───────────────────────────

  property "mdoc DeviceResponse verification: Attesto never accepts what @auth0/mdl rejects", %{keys: k} do
    check all(item <- mdoc_generator(k), max_runs: @fuzz_runs) do
      att_res = Mdoc.verify_device_response(item.dr_bytes, item.context, item.issuer_jwk, now: item.now)

      js_res =
        js_call(:fuzzVerifyMdocDeviceResponse, [
          item.dr_b64,
          item.session_transcript_b64,
          item.issuer_jwk,
          %{"now" => item.now}
        ])

      case att_res do
        {:ok, [verified]} ->
          assert item.mutation == :valid
          assert js_res["ok"] == true
          [js_doc] = js_res["documents"]
          assert js_doc["doc_type"] == verified.doc_type
          assert js_doc["namespaces"] == verified.namespaces

        {:error, _reason} ->
          if js_res["ok"] == true do
            assert Map.fetch(@mdoc_strict_rejections, item.mutation) == {:ok, att_res}
          else
            assert js_res["ok"] == false
          end
      end
    end
  end

  # ── Property 5: DPoP Proof Verification ────────────────────────────────────

  property "DPoP proof verification: Attesto never accepts what joserfc or jose rejects", %{keys: k} do
    check all(item <- dpop_generator(k), max_runs: @fuzz_runs) do
      att_res = DPoP.verify_proof(item.proof, item.opts)

      oracle_opts = %{
        "http_method" => Keyword.fetch!(item.opts, :http_method),
        "http_uri" => Keyword.fetch!(item.opts, :http_uri),
        "now" => Keyword.fetch!(item.opts, :now),
        "max_age_seconds" => Keyword.get(item.opts, :max_age_seconds, 60),
        "access_token" => Keyword.get(item.opts, :access_token)
      }

      py_res = py_eval("fuzz_verify_dpop(p, o)", %{"p" => item.proof, "o" => oracle_opts})
      js_res = js_call(:fuzzVerifyDpop, [item.proof, oracle_opts])

      case att_res do
        {:ok, verified} ->
          assert item.mutation == :valid
          assert py_res["ok"] == true
          assert js_res["ok"] == true
          assert py_res["jkt"] == verified.jkt
          assert js_res["jkt"] == verified.jkt
          assert py_res["jti"] == verified.jti
          assert js_res["jti"] == verified.jti

        {:error, _reason} ->
          if py_res["ok"] == true or js_res["ok"] == true do
            assert Map.fetch(@dpop_strict_rejections, item.mutation) == {:ok, att_res}
          else
            assert py_res["ok"] == false
            assert js_res["ok"] == false
          end
      end
    end
  end

  # ── Generators & Helpers ───────────────────────────────────────────────────

  defp py_eval(expr, bindings) do
    PythonBridge.eval_wrapped!(
      "__import__('attesto_compat')." <> expr,
      bindings,
      paths: [@py_path]
    )
  end

  defp js_call(fun, args) do
    NodeBridge.call!("attesto_compat", fun, args)
  end

  defp verify_jws_attesto(%{jwt: jwt, jwk: jwk, algs: algs}) do
    with {:ok, header} <- JWS.protected_header(jwt) do
      JWS.verify_trusted(jwt, header, jwk, accepted_algs: algs, claims_map?: true)
    end
  end

  defp verify_sd_jwt_attesto(%{combined: combined, issuer_jwk: issuer_jwk, holder_jwk: holder_jwk, kb_opts: kb_opts}) do
    with {:ok, verified} <- SdJwt.verify(combined, issuer_jwk, accepted_algs: ["ES256"]),
         :ok <- maybe_verify_kb(verified, holder_jwk, kb_opts) do
      {:ok, verified.claims}
    end
  end

  defp maybe_verify_kb(verified, holder_jwk, %{"require_kb" => true} = kb_opts) do
    SdJwt.verify_key_binding(verified, holder_jwk,
      nonce: kb_opts["nonce"],
      audience: kb_opts["audience"],
      now: kb_opts["now"]
    )
  end

  defp maybe_verify_kb(_verified, _holder_jwk, _kb_opts), do: :ok

  defp make_non_canonical_b64url(b64) when is_binary(b64) do
    alphabet = ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    len = byte_size(b64)

    case rem(len, 4) do
      r when r in [2, 3] ->
        prefix = binary_part(b64, 0, len - 1)
        last_char = :binary.at(b64, len - 1)
        idx = Enum.find_index(alphabet, &(&1 == last_char))
        mutated_idx = Bitwise.bxor(idx, 1)
        mutated_char = Enum.at(alphabet, mutated_idx)
        prefix <> <<mutated_char>>

      _ ->
        b64
    end
  end

  defp non_canonical_json_b64(json_str) do
    b64 = JWS.encode64(json_str)

    if rem(byte_size(b64), 4) in [2, 3] do
      make_non_canonical_b64url(b64)
    else
      make_non_canonical_b64url(JWS.encode64(json_str <> " "))
    end
  end

  defp sign_raw_segments(pem, alg, protected_b64, payload_b64) do
    jwk = JOSE.JWK.from_pem(pem)
    signing_input = protected_b64 <> "." <> payload_b64
    {_kty, raw_key} = JOSE.JWK.to_key(jwk)

    sig =
      case alg do
        "ES256" ->
          der = :public_key.sign(signing_input, :sha256, raw_key)
          {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
          <<r::unsigned-big-size(256), s::unsigned-big-size(256)>>

        "RS256" ->
          :public_key.sign(signing_input, :sha256, raw_key)

        "PS256" ->
          :public_key.sign(signing_input, :sha256, raw_key,
            rsa_padding: :rsa_pkcs1_pss_padding,
            rsa_pss_saltlen: 32,
            rsa_mgf1_md: :sha256
          )
      end

    signing_input <> "." <> JWS.encode64(sig)
  end

  defp deep_nested_json(depth, leaf) when depth <= 0, do: JSON.encode!(leaf)

  defp deep_nested_json(depth, leaf) do
    "{\"a\":" <> deep_nested_json(depth - 1, leaf) <> "}"
  end

  defp jws_generator(k) do
    gen all(
          sub <- StreamData.string(:alphanumeric, min_length: 1, max_length: 10),
          extra_val <- StreamData.integer(0..200),
          alg <- StreamData.member_of(["ES256", "PS256", "RS256"]),
          mutation <-
            StreamData.member_of([
              :valid,
              :tamper_sig,
              :tamper_payload,
              :alg_none,
              :duplicate_header_key,
              :duplicate_payload_key,
              :non_canonical_b64_payload,
              :non_canonical_b64_sig,
              :padded_b64_payload,
              :deep_json_payload,
              :crit_unsupported,
              :crit_empty,
              :ps256_zero_salt,
              :rsa_jwk_without_explicit_ps256_alg,
              :ecdsa_zero_padded_sig,
              :private_key_in_jwk,
              :wrong_use_in_jwk,
              :non_object_payload,
              :extra_segment,
              :truncated_segment
            ])
        ) do
      pem = if alg == "ES256", do: k.ec_pem, else: k.rsa_pem
      pub_map = if alg == "ES256", do: k.ec_pub_map, else: Map.put(k.rsa_pub_map, "alg", alg)
      claims = %{"sub" => sub, "n" => extra_val}
      header = %{"alg" => alg, "typ" => "JWT"}

      base_jwt = JWS.sign_compact(pem, header, claims)
      [h_b64, p_b64, s_b64] = String.split(base_jwt, ".")

      ctx = %{
        k: k,
        pem: pem,
        alg: alg,
        pub_map: pub_map,
        claims: claims,
        base_jwt: base_jwt,
        h_b64: h_b64,
        p_b64: p_b64,
        s_b64: s_b64,
        sub: sub
      }

      {jwt, jwk, accepted_algs} = mutate_jws(mutation, ctx)

      %{mutation: mutation, jwt: jwt, jwk: jwk, algs: accepted_algs}
    end
  end

  defp mutate_jws(:valid, c), do: {c.base_jwt, c.pub_map, [c.alg]}

  defp mutate_jws(:tamper_sig, c) do
    {:ok, <<first, rest::binary>>} = Base.url_decode64(c.s_b64, padding: false)
    bad_s = JWS.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
    {c.h_b64 <> "." <> c.p_b64 <> "." <> bad_s, c.pub_map, [c.alg]}
  end

  defp mutate_jws(:tamper_payload, c) do
    bad_p = JWS.encode64(JSON.encode!(Map.put(c.claims, "sub", c.sub <> "!")))
    {c.h_b64 <> "." <> bad_p <> "." <> c.s_b64, c.pub_map, [c.alg]}
  end

  defp mutate_jws(:alg_none, c) do
    none_h = JWS.encode64(JSON.encode!(%{"alg" => "none", "typ" => "JWT"}))
    {none_h <> "." <> c.p_b64 <> ".", c.pub_map, [c.alg]}
  end

  defp mutate_jws(:duplicate_header_key, c) do
    dup_h = JWS.encode64(~s({"alg":"#{c.alg}","typ":"JWT","typ":"JWT"}))
    {sign_raw_segments(c.pem, c.alg, dup_h, c.p_b64), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:duplicate_payload_key, c) do
    dup_p = JWS.encode64(~s({"sub":"#{c.sub}","sub":"#{c.sub}"}))
    {sign_raw_segments(c.pem, c.alg, c.h_b64, dup_p), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:non_canonical_b64_payload, c) do
    nc_p = non_canonical_json_b64(JSON.encode!(c.claims))
    {sign_raw_segments(c.pem, c.alg, c.h_b64, nc_p), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:non_canonical_b64_sig, c) do
    es_jwt = JWS.sign_compact(c.k.ec_pem, %{"alg" => "ES256", "typ" => "JWT"}, c.claims)
    [eh, ep, es] = String.split(es_jwt, ".")
    {eh <> "." <> ep <> "." <> make_non_canonical_b64url(es), c.k.ec_pub_map, ["ES256"]}
  end

  defp mutate_jws(:padded_b64_payload, c) do
    padded_p = Base.url_encode64(~s({"sub":"#{c.sub}"}), padding: true)
    final_p = if String.ends_with?(padded_p, "="), do: padded_p, else: padded_p <> "="
    {sign_raw_segments(c.pem, c.alg, c.h_b64, final_p), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:deep_json_payload, c) do
    deep_p = JWS.encode64(deep_nested_json(35, %{"sub" => c.sub}))
    {sign_raw_segments(c.pem, c.alg, c.h_b64, deep_p), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:crit_unsupported, c) do
    crit_h = JWS.encode64(JSON.encode!(%{"alg" => c.alg, "crit" => ["x"], "x" => c.sub}))
    {sign_raw_segments(c.pem, c.alg, crit_h, c.p_b64), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:crit_empty, c) do
    crit_h = JWS.encode64(JSON.encode!(%{"alg" => c.alg, "crit" => []}))
    {sign_raw_segments(c.pem, c.alg, crit_h, c.p_b64), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:ps256_zero_salt, c) do
    ps_h = JWS.encode64(JSON.encode!(%{"alg" => "PS256", "typ" => "JWT"}))
    signing_input = ps_h <> "." <> c.p_b64
    sig_b64 = py_eval("sign_ps256_custom_salt(si, pem, 0)", %{"si" => signing_input, "pem" => c.k.rsa_pem})
    {signing_input <> "." <> sig_b64, Map.put(c.k.rsa_pub_map, "alg", "PS256"), ["PS256"]}
  end

  defp mutate_jws(:rsa_jwk_without_explicit_ps256_alg, c) do
    ps_jwt = JWS.sign_compact(c.k.rsa_pem, %{"alg" => "PS256", "typ" => "JWT"}, c.claims)
    {ps_jwt, c.k.rsa_pub_map, ["PS256"]}
  end

  defp mutate_jws(:ecdsa_zero_padded_sig, c) do
    es_jwt = JWS.sign_compact(c.k.ec_pem, %{"alg" => "ES256", "typ" => "JWT"}, c.claims)
    [eh, ep, es] = String.split(es_jwt, ".")
    {:ok, <<r::binary-size(32), s::binary-size(32)>>} = Base.url_decode64(es, padding: false)
    {eh <> "." <> ep <> "." <> JWS.encode64(<<0, r::binary, 0, s::binary>>), c.k.ec_pub_map, ["ES256"]}
  end

  defp mutate_jws(:private_key_in_jwk, c) do
    es_jwt = JWS.sign_compact(c.k.ec_pem, %{"alg" => "ES256", "typ" => "JWT"}, c.claims)
    {es_jwt, c.k.ec_priv_map, ["ES256"]}
  end

  defp mutate_jws(:wrong_use_in_jwk, c) do
    es_jwt = JWS.sign_compact(c.k.ec_pem, %{"alg" => "ES256", "typ" => "JWT"}, c.claims)
    {es_jwt, Map.put(c.k.ec_pub_map, "use", "enc"), ["ES256"]}
  end

  defp mutate_jws(:non_object_payload, c) do
    arr_p = JWS.encode64(JSON.encode!([c.sub]))
    {sign_raw_segments(c.pem, c.alg, c.h_b64, arr_p), c.pub_map, [c.alg]}
  end

  defp mutate_jws(:extra_segment, c), do: {c.base_jwt <> ".extra", c.pub_map, [c.alg]}
  defp mutate_jws(:truncated_segment, c), do: {c.h_b64 <> "." <> c.p_b64, c.pub_map, [c.alg]}

  defp jwe_generator(k) do
    gen all(
          plaintext <- StreamData.binary(min_length: 1, max_length: 24),
          enc <- StreamData.member_of(["A128GCM", "A256GCM"]),
          mutation <-
            StreamData.member_of([
              :valid,
              :tamper_ciphertext,
              :tamper_tag,
              :tamper_iv,
              :tamper_header,
              :non_empty_encrypted_key,
              :wrong_iv_length,
              :wrong_tag_length,
              :zip_def,
              :non_canonical_apu,
              :non_base64_apu,
              :crit_in_header,
              :duplicate_header_key,
              :epk_with_private_d,
              :non_canonical_b64_tag,
              :wrong_recipient_key,
              :extra_segment,
              :truncated_segment
            ])
        ) do
      base_hdr = %{"alg" => "ECDH-ES", "enc" => enc}
      {:ok, base_jwe} = JWE.encrypt(k.ec_pub_map, plaintext, base_hdr)
      [h_b64, ek_b64, iv_b64, ct_b64, tag_b64] = String.split(base_jwe, ".")

      ctx = %{
        k: k,
        plaintext: plaintext,
        enc: enc,
        base_jwe: base_jwe,
        h_b64: h_b64,
        ek_b64: ek_b64,
        iv_b64: iv_b64,
        ct_b64: ct_b64,
        tag_b64: tag_b64
      }

      {compact, priv_jwk} = mutate_jwe(mutation, ctx)

      %{
        mutation: mutation,
        compact: compact,
        priv_jwk: priv_jwk,
        plaintext_b64: JWS.encode64(plaintext)
      }
    end
  end

  defp mutate_jwe(:valid, c), do: {c.base_jwe, c.k.ec_priv_map}

  defp mutate_jwe(:tamper_ciphertext, c) do
    {:ok, <<b0, rest::binary>>} = Base.url_decode64(c.ct_b64, padding: false)
    bad_ct = JWS.encode64(<<Bitwise.bxor(b0, 1), rest::binary>>)
    {Enum.join([c.h_b64, c.ek_b64, c.iv_b64, bad_ct, c.tag_b64], "."), c.k.ec_priv_map}
  end

  defp mutate_jwe(:tamper_tag, c) do
    {:ok, <<b0, rest::binary>>} = Base.url_decode64(c.tag_b64, padding: false)
    bad_tag = JWS.encode64(<<Bitwise.bxor(b0, 1), rest::binary>>)
    {Enum.join([c.h_b64, c.ek_b64, c.iv_b64, c.ct_b64, bad_tag], "."), c.k.ec_priv_map}
  end

  defp mutate_jwe(:tamper_iv, c) do
    {:ok, <<b0, rest::binary>>} = Base.url_decode64(c.iv_b64, padding: false)
    bad_iv = JWS.encode64(<<Bitwise.bxor(b0, 1), rest::binary>>)
    {Enum.join([c.h_b64, c.ek_b64, bad_iv, c.ct_b64, c.tag_b64], "."), c.k.ec_priv_map}
  end

  defp mutate_jwe(:tamper_header, c) do
    {:ok, raw_h} = Base.url_decode64(c.h_b64, padding: false)
    bad_h = JWS.encode64(JSON.encode!(Map.put(JSON.decode!(raw_h), "kid", "tampered")))
    {Enum.join([bad_h, c.ek_b64, c.iv_b64, c.ct_b64, c.tag_b64], "."), c.k.ec_priv_map}
  end

  defp mutate_jwe(:non_empty_encrypted_key, c),
    do: {Enum.join([c.h_b64, JWS.encode64("ek"), c.iv_b64, c.ct_b64, c.tag_b64], "."), c.k.ec_priv_map}

  defp mutate_jwe(:wrong_iv_length, c),
    do: {Enum.join([c.h_b64, c.ek_b64, JWS.encode64(<<0::64>>), c.ct_b64, c.tag_b64], "."), c.k.ec_priv_map}

  defp mutate_jwe(:wrong_tag_length, c),
    do: {Enum.join([c.h_b64, c.ek_b64, c.iv_b64, c.ct_b64, JWS.encode64(<<0::96>>)], "."), c.k.ec_priv_map}

  defp mutate_jwe(:zip_def, c) do
    zip_jwe =
      py_eval("fuzz_encrypt_jwe(pub, pt, hdr)", %{
        "pub" => c.k.ec_pub_map,
        "pt" => JWS.encode64(c.plaintext),
        "hdr" => %{"alg" => "ECDH-ES", "enc" => c.enc, "zip" => "DEF"}
      })

    {zip_jwe, c.k.ec_priv_map}
  end

  defp mutate_jwe(:non_canonical_apu, c) do
    jwe =
      encrypt_custom_jwe_header(
        c.k.ec_pub_map,
        c.plaintext,
        c.enc,
        fn epk_map ->
          JSON.encode!(%{"alg" => "ECDH-ES", "enc" => c.enc, "apu" => "YR", "epk" => epk_map})
        end,
        false,
        "a"
      )

    {jwe, c.k.ec_priv_map}
  end

  defp mutate_jwe(:non_base64_apu, c) do
    jwe =
      encrypt_custom_jwe_header(
        c.k.ec_pub_map,
        c.plaintext,
        c.enc,
        fn epk_map ->
          JSON.encode!(%{"alg" => "ECDH-ES", "enc" => c.enc, "apu" => "not base64!", "epk" => epk_map})
        end,
        false,
        <<158, 139, 91, 106, 199, 186>>
      )

    {jwe, c.k.ec_priv_map}
  end

  defp mutate_jwe(:crit_in_header, c) do
    jwe_crit =
      py_eval("fuzz_encrypt_jwe(pub, pt, hdr)", %{
        "pub" => c.k.ec_pub_map,
        "pt" => JWS.encode64(c.plaintext),
        "hdr" => %{"alg" => "ECDH-ES", "enc" => c.enc, "crit" => ["enc"]}
      })

    {jwe_crit, c.k.ec_priv_map}
  end

  defp mutate_jwe(:duplicate_header_key, c) do
    dup_jwe =
      encrypt_custom_jwe_header(c.k.ec_pub_map, c.plaintext, c.enc, fn epk_map ->
        ~s({"alg":"ECDH-ES","enc":"#{c.enc}","typ":"JWE","typ":"JWE","epk":#{JSON.encode!(epk_map)}})
      end)

    {dup_jwe, c.k.ec_priv_map}
  end

  defp mutate_jwe(:epk_with_private_d, c) do
    epk_d_jwe =
      encrypt_custom_jwe_header(
        c.k.ec_pub_map,
        c.plaintext,
        c.enc,
        fn epk_full_map ->
          ~s({"alg":"ECDH-ES","enc":"#{c.enc}","epk":#{JSON.encode!(epk_full_map)}})
        end,
        true
      )

    {epk_d_jwe, c.k.ec_priv_map}
  end

  defp mutate_jwe(:non_canonical_b64_tag, c) do
    nc_tag = make_non_canonical_b64url(c.tag_b64)
    {Enum.join([c.h_b64, c.ek_b64, c.iv_b64, c.ct_b64, nc_tag], "."), c.k.ec_priv_map}
  end

  defp mutate_jwe(:wrong_recipient_key, c), do: {c.base_jwe, c.k.ec2_priv_map}
  defp mutate_jwe(:extra_segment, c), do: {c.base_jwe <> ".extra", c.k.ec_priv_map}

  defp mutate_jwe(:truncated_segment, c), do: {Enum.join([c.h_b64, c.ek_b64, c.iv_b64, c.ct_b64], "."), c.k.ec_priv_map}

  defp encrypt_custom_jwe_header(
         recipient_pub_map,
         plaintext,
         enc,
         header_json_fn,
         include_d? \\ false,
         apu_bytes \\ <<>>
       ) do
    ephemeral = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, epk_map} = if include_d?, do: JOSE.JWK.to_map(ephemeral), else: JOSE.JWK.to_public_map(ephemeral)
    protected_json = header_json_fn.(epk_map)
    protected_b64 = JWS.encode64(protected_json)

    recipient_jwk = JOSE.JWK.from_map(recipient_pub_map)
    z = JOSE.JWK.shared_secret(recipient_jwk, ephemeral)
    key_bits = if enc == "A128GCM", do: 128, else: 256

    other_info =
      <<byte_size(enc)::32-big, enc::binary, byte_size(apu_bytes)::32-big, apu_bytes::binary, 0::32-big,
        key_bits::32-big>>

    cek = binary_part(:crypto.hash(:sha256, <<1::32-big, z::binary, other_info::binary>>), 0, div(key_bits, 8))
    iv = :crypto.strong_rand_bytes(12)
    cipher = if enc == "A128GCM", do: :aes_128_gcm, else: :aes_256_gcm
    {ciphertext, tag} = :crypto.crypto_one_time_aead(cipher, cek, iv, plaintext, protected_b64, 16, true)

    Enum.join([protected_b64, "", JWS.encode64(iv), JWS.encode64(ciphertext), JWS.encode64(tag)], ".")
  end

  defp sd_jwt_generator(k) do
    gen all(
          given_name <- StreamData.string(:alphanumeric, min_length: 1, max_length: 8),
          family_name <- StreamData.string(:alphanumeric, min_length: 1, max_length: 8),
          sd_alg <- StreamData.member_of(["sha-256", "sha-384", "sha-512"]),
          mutation <-
            StreamData.member_of([
              :valid,
              :valid_with_kb,
              :unused_disclosure,
              :duplicate_disclosure,
              :duplicate_sd_digest,
              :cleartext_claim_collision,
              :reserved_claim_in_disclosure,
              :nested_sd_alg,
              :non_string_salt_in_disclosure,
              :non_string_name_in_disclosure,
              :array_disclosure_in_object_sd,
              :object_disclosure_in_array_slot,
              :unsupported_sd_alg,
              :empty_disclosure_segment,
              :missing_trailing_tilde,
              :padded_b64_disclosure,
              :non_canonical_b64_disclosure,
              :duplicate_json_in_disclosure,
              :deep_json_in_disclosure,
              :tampered_kb_sd_hash,
              :tampered_kb_nonce
            ])
        ) do
      {combined, kb_opts} = build_mutated_sd_jwt(k, given_name, family_name, sd_alg, mutation)

      %{
        mutation: mutation,
        combined: combined,
        issuer_jwk: k.ec_pub_map,
        holder_jwk: k.ec2_pub_map,
        kb_opts: kb_opts
      }
    end
  end

  defp build_mutated_sd_jwt(k, given_name, family_name, sd_alg, mutation) do
    salt1 = "salt_" <> given_name
    salt2 = "salt_" <> family_name
    d1 = SdJwt.object_disclosure(salt1, "given_name", given_name)
    d2 = SdJwt.object_disclosure(salt2, "family_name", family_name)
    arr_d = SdJwt.array_disclosure(salt2, family_name)

    dig1 = SdJwt.digest(d1, sd_alg)
    dig2 = SdJwt.digest(d2, sd_alg)
    arr_dig = SdJwt.digest(arr_d, sd_alg)

    header = %{"alg" => "ES256", "typ" => "vc+sd-jwt"}
    base_payload = %{"iss" => "https://issuer.example", "_sd_alg" => sd_alg, "_sd" => [dig1, dig2]}
    base_jwt = JWS.sign_compact(k.ec_pem, header, base_payload)

    ctx = %{
      k: k,
      given_name: given_name,
      sd_alg: sd_alg,
      salt1: salt1,
      d1: d1,
      arr_d: arr_d,
      dig1: dig1,
      arr_dig: arr_dig,
      header: header,
      base_payload: base_payload,
      base_jwt: base_jwt
    }

    mutate_sd_jwt(mutation, ctx)
  end

  defp mutate_sd_jwt(:valid, c), do: {c.base_jwt <> "~" <> c.d1 <> "~", nil}

  defp mutate_sd_jwt(:valid_with_kb, c) do
    pres = c.base_jwt <> "~" <> c.d1 <> "~"
    sd_hash = SdJwt.digest(pres, c.sd_alg)

    kb_jwt =
      JWS.sign_compact(
        c.k.ec2_pem,
        %{"alg" => "ES256", "typ" => "kb+jwt"},
        %{"nonce" => "n1", "aud" => "https://v.example", "iat" => 1_700_000_000, "sd_hash" => sd_hash}
      )

    {pres <> kb_jwt,
     %{"require_kb" => true, "nonce" => "n1", "audience" => "https://v.example", "now" => 1_700_000_000}}
  end

  defp mutate_sd_jwt(:unused_disclosure, c) do
    extra_d = SdJwt.object_disclosure("s_unused", "extra", "val")
    {c.base_jwt <> "~" <> c.d1 <> "~" <> extra_d <> "~", nil}
  end

  defp mutate_sd_jwt(:duplicate_disclosure, c), do: {c.base_jwt <> "~" <> c.d1 <> "~" <> c.d1 <> "~", nil}

  defp mutate_sd_jwt(:duplicate_sd_digest, c) do
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [c.dig1, c.dig1]))
    {jwt <> "~" <> c.d1 <> "~", nil}
  end

  defp mutate_sd_jwt(:cleartext_claim_collision, c) do
    jwt =
      JWS.sign_compact(
        c.k.ec_pem,
        c.header,
        Map.merge(c.base_payload, %{"given_name" => "cleartext", "_sd" => [c.dig1]})
      )

    {jwt <> "~" <> c.d1 <> "~", nil}
  end

  defp mutate_sd_jwt(:reserved_claim_in_disclosure, c) do
    res_d = SdJwt.object_disclosure(c.salt1, "_sd", ["x"])
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [SdJwt.digest(res_d, c.sd_alg)]))
    {jwt <> "~" <> res_d <> "~", nil}
  end

  defp mutate_sd_jwt(:nested_sd_alg, c) do
    nested = Map.merge(c.base_payload, %{"_sd" => [c.dig1], "address" => %{"_sd_alg" => c.sd_alg, "city" => "NY"}})
    {JWS.sign_compact(c.k.ec_pem, c.header, nested) <> "~" <> c.d1 <> "~", nil}
  end

  defp mutate_sd_jwt(:non_string_salt_in_disclosure, c) do
    bad_d = JWS.encode64(JSON.encode!([123, "given_name", c.given_name]))
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [SdJwt.digest(bad_d, c.sd_alg)]))
    {jwt <> "~" <> bad_d <> "~", nil}
  end

  defp mutate_sd_jwt(:non_string_name_in_disclosure, c) do
    bad_d = JWS.encode64(JSON.encode!([c.salt1, 123, c.given_name]))
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [SdJwt.digest(bad_d, c.sd_alg)]))
    {jwt <> "~" <> bad_d <> "~", nil}
  end

  defp mutate_sd_jwt(:array_disclosure_in_object_sd, c) do
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [c.arr_dig]))
    {jwt <> "~" <> c.arr_d <> "~", nil}
  end

  defp mutate_sd_jwt(:object_disclosure_in_array_slot, c) do
    bad_payload = %{"iss" => "https://issuer.example", "_sd_alg" => c.sd_alg, "items" => [%{"..." => c.dig1}]}
    {JWS.sign_compact(c.k.ec_pem, c.header, bad_payload) <> "~" <> c.d1 <> "~", nil}
  end

  defp mutate_sd_jwt(:unsupported_sd_alg, c) do
    bad_payload = %{"iss" => "https://issuer.example", "_sd_alg" => "md5", "_sd" => [c.dig1]}
    {JWS.sign_compact(c.k.ec_pem, c.header, bad_payload) <> "~" <> c.d1 <> "~", nil}
  end

  defp mutate_sd_jwt(:empty_disclosure_segment, c), do: {c.base_jwt <> "~~" <> c.d1 <> "~", nil}
  defp mutate_sd_jwt(:missing_trailing_tilde, c), do: {c.base_jwt, nil}

  defp mutate_sd_jwt(:padded_b64_disclosure, c) do
    padded_d = "WyJzIiwiYSIsMV0="
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [SdJwt.digest(padded_d, c.sd_alg)]))
    {jwt <> "~" <> padded_d <> "~", nil}
  end

  defp mutate_sd_jwt(:non_canonical_b64_disclosure, c) do
    nc_d = "WyJzIiwiYSIsMV1"
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [SdJwt.digest(nc_d, c.sd_alg)]))
    {jwt <> "~" <> nc_d <> "~", nil}
  end

  defp mutate_sd_jwt(:duplicate_json_in_disclosure, c) do
    dup_d = JWS.encode64(~s(["s","profile",{"admin":true,"admin":false}]))
    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [SdJwt.digest(dup_d, c.sd_alg)]))
    {jwt <> "~" <> dup_d <> "~", nil}
  end

  defp mutate_sd_jwt(:deep_json_in_disclosure, c) do
    deep_d =
      JWS.encode64(~s(["s","deep",) <> String.duplicate("[", 33) <> "1" <> String.duplicate("]", 33) <> "]")

    jwt = JWS.sign_compact(c.k.ec_pem, c.header, Map.put(c.base_payload, "_sd", [SdJwt.digest(deep_d, c.sd_alg)]))
    {jwt <> "~" <> deep_d <> "~", nil}
  end

  defp mutate_sd_jwt(:tampered_kb_sd_hash, c) do
    kb_jwt =
      JWS.sign_compact(
        c.k.ec2_pem,
        %{"alg" => "ES256", "typ" => "kb+jwt"},
        %{"nonce" => "n1", "aud" => "https://v.example", "iat" => 1_700_000_000, "sd_hash" => "wrong_hash"}
      )

    {c.base_jwt <> "~" <> c.d1 <> "~" <> kb_jwt,
     %{"require_kb" => true, "nonce" => "n1", "audience" => "https://v.example", "now" => 1_700_000_000}}
  end

  defp mutate_sd_jwt(:tampered_kb_nonce, c) do
    pres = c.base_jwt <> "~" <> c.d1 <> "~"
    sd_hash = SdJwt.digest(pres, c.sd_alg)

    kb_jwt =
      JWS.sign_compact(
        c.k.ec2_pem,
        %{"alg" => "ES256", "typ" => "kb+jwt"},
        %{"nonce" => "wrong_nonce", "aud" => "https://v.example", "iat" => 1_700_000_000, "sd_hash" => sd_hash}
      )

    {pres <> kb_jwt,
     %{"require_kb" => true, "nonce" => "n1", "audience" => "https://v.example", "now" => 1_700_000_000}}
  end

  defp mdoc_generator(k) do
    gen all(
          given_name <- StreamData.string(:alphanumeric, min_length: 1, max_length: 8),
          nonce <- StreamData.string(:alphanumeric, min_length: 4, max_length: 8),
          mutation <-
            StreamData.member_of([
              :valid,
              :short_item_random,
              :duplicate_element_identifier,
              :missing_dr_version,
              :wrong_dr_version,
              :non_map_device_signed_items,
              :tampered_element_value,
              :missing_value_digest,
              :tampered_device_signature,
              :tampered_issuer_signature,
              :handover_nonce_mismatch,
              :doc_type_mismatch_outer_vs_mso,
              :expired_mso,
              :not_yet_valid_mso,
              :device_mac_instead_of_signature,
              :non_zero_status,
              :trailing_cbor_bytes,
              :untagged_device_namespaces
            ])
        ) do
      doc_type = "org.iso.18013.5.1.mDL"
      ns = "org.iso.18013.5.1"
      now = 1_700_000_000
      context = [client_id: "https://verifier.example", nonce: nonce, response_uri: "https://verifier.example/resp"]
      {:ok, session_transcript} = Mdoc.session_transcript(context)
      session_transcript_b64 = session_transcript |> CBOR.encode() |> JWS.encode64()

      {dr_bytes, verify_now} =
        build_mutated_mdoc(k, doc_type, ns, given_name, now, session_transcript, mutation)

      %{
        mutation: mutation,
        dr_b64: JWS.encode64(dr_bytes),
        dr_bytes: dr_bytes,
        context: context,
        session_transcript_b64: session_transcript_b64,
        issuer_jwk: k.ec_pub_map,
        now: verify_now
      }
    end
  end

  defp build_mutated_mdoc(k, doc_type, ns, given_name, now, session_transcript, mutation) do
    rand_bytes = mdoc_random_bytes(mutation)

    item0 =
      tag24(%{
        "digestID" => 0,
        "elementIdentifier" => "given_name",
        "elementValue" => given_name,
        "random" => cbor_bytes(rand_bytes)
      })

    dig0 = item_digest(item0)
    {items, digests} = mdoc_items_and_digests(mutation, item0, dig0, given_name, rand_bytes)

    mso = %{
      "version" => "1.0",
      "digestAlgorithm" => "SHA-256",
      "docType" => doc_type,
      "valueDigests" => %{ns => digests},
      "deviceKeyInfo" => %{"deviceKey" => Cose.key_to_cose(k.ec2_pub_map)},
      "validityInfo" => %{
        "signed" => tag0_time(now - 100),
        "validFrom" => tag0_time(now - 100),
        "validUntil" => tag0_time(now + 3600)
      }
    }

    mso_payload = mso |> tag24() |> CBOR.encode()
    {:ok, raw_issuer_auth, ""} = k.ec_pem |> Cose.sign1(mso_payload, []) |> CBOR.decode()
    issuer_auth = maybe_tamper_cose_sig(raw_issuer_auth, mutation == :tampered_issuer_signature)

    outer_doc_type = mdoc_outer_doc_type(mutation, doc_type)
    dev_ns_tagged = mdoc_dev_ns_tagged(mutation, ns)
    signing_transcript = mdoc_signing_transcript(mutation, session_transcript)

    dev_auth_bytes = Mdoc.device_authentication_bytes(signing_transcript, outer_doc_type, dev_ns_tagged)
    {:ok, raw_dev_sig, ""} = k.ec2_pem |> Cose.sign1_detached(dev_auth_bytes, []) |> CBOR.decode()
    dev_sig = maybe_tamper_cose_sig(raw_dev_sig, mutation == :tampered_device_signature)

    device_signed = mdoc_device_signed(mutation, dev_ns_tagged, dev_sig)
    dr_map = build_dr_map(mutation, outer_doc_type, issuer_auth, ns, items, device_signed)
    dr_bytes = mdoc_encode_dr_bytes(mutation, dr_map)
    verify_now = mdoc_verify_now(mutation, now)

    {dr_bytes, verify_now}
  end

  defp mdoc_random_bytes(:short_item_random), do: :crypto.strong_rand_bytes(8)
  defp mdoc_random_bytes(_mutation), do: :crypto.strong_rand_bytes(16)

  defp maybe_tamper_cose_sig([p, u, pay, %CBOR.Tag{tag: :bytes, value: <<b0, rest::binary>>}], true),
    do: [p, u, pay, cbor_bytes(<<Bitwise.bxor(b0, 1), rest::binary>>)]

  defp maybe_tamper_cose_sig(cose_arr, false), do: cose_arr

  defp mdoc_outer_doc_type(:doc_type_mismatch_outer_vs_mso, _doc_type), do: "org.iso.18013.5.1.other"
  defp mdoc_outer_doc_type(_mutation, doc_type), do: doc_type

  defp mdoc_dev_ns_tagged(:non_map_device_signed_items, ns), do: tag24(%{ns => 123})
  defp mdoc_dev_ns_tagged(_mutation, _ns), do: tag24(%{})

  defp mdoc_signing_transcript(:handover_nonce_mismatch, _session_transcript) do
    {:ok, wrong_st} =
      Mdoc.session_transcript(
        client_id: "https://verifier.example",
        nonce: "wrong_nonce",
        response_uri: "https://verifier.example/resp"
      )

    wrong_st
  end

  defp mdoc_signing_transcript(_mutation, session_transcript), do: session_transcript

  defp mdoc_device_signed(:device_mac_instead_of_signature, dev_ns_tagged, dev_sig),
    do: %{"nameSpaces" => dev_ns_tagged, "deviceAuth" => %{"deviceMac" => dev_sig}}

  defp mdoc_device_signed(:untagged_device_namespaces, _dev_ns_tagged, dev_sig),
    do: %{"nameSpaces" => %{}, "deviceAuth" => %{"deviceSignature" => dev_sig}}

  defp mdoc_device_signed(_mutation, dev_ns_tagged, dev_sig),
    do: %{"nameSpaces" => dev_ns_tagged, "deviceAuth" => %{"deviceSignature" => dev_sig}}

  defp mdoc_encode_dr_bytes(:trailing_cbor_bytes, dr_map), do: CBOR.encode(dr_map) <> <<0>>
  defp mdoc_encode_dr_bytes(_mutation, dr_map), do: CBOR.encode(dr_map)

  defp mdoc_verify_now(:expired_mso, now), do: now + 7200
  defp mdoc_verify_now(:not_yet_valid_mso, now), do: now - 7200
  defp mdoc_verify_now(_mutation, now), do: now

  defp mdoc_items_and_digests(:duplicate_element_identifier, item0, dig0, given_name, _rand_bytes) do
    item1 =
      tag24(%{
        "digestID" => 1,
        "elementIdentifier" => "given_name",
        "elementValue" => given_name <> "_dup",
        "random" => cbor_bytes(:crypto.strong_rand_bytes(16))
      })

    {[item0, item1], %{0 => dig0, 1 => item_digest(item1)}}
  end

  defp mdoc_items_and_digests(:tampered_element_value, _item0, dig0, given_name, rand_bytes) do
    tampered_item0 =
      tag24(%{
        "digestID" => 0,
        "elementIdentifier" => "given_name",
        "elementValue" => given_name <> "_tampered",
        "random" => cbor_bytes(rand_bytes)
      })

    {[tampered_item0], %{0 => dig0}}
  end

  defp mdoc_items_and_digests(:missing_value_digest, item0, dig0, _given_name, _rand_bytes),
    do: {[item0], %{99 => dig0}}

  defp mdoc_items_and_digests(_mutation, item0, dig0, _given_name, _rand_bytes), do: {[item0], %{0 => dig0}}

  defp build_dr_map(mutation, outer_doc_type, issuer_auth, ns, items, device_signed) do
    base = %{
      "version" => "1.0",
      "documents" => [
        %{
          "docType" => outer_doc_type,
          "issuerSigned" => %{"issuerAuth" => issuer_auth, "nameSpaces" => %{ns => items}},
          "deviceSigned" => device_signed
        }
      ],
      "status" => if(mutation == :non_zero_status, do: 1, else: 0)
    }

    case mutation do
      :missing_dr_version -> Map.delete(base, "version")
      :wrong_dr_version -> Map.put(base, "version", "2.0")
      _ -> base
    end
  end

  defp tag24(val), do: %CBOR.Tag{tag: 24, value: cbor_bytes(CBOR.encode(val))}
  defp cbor_bytes(bin), do: %CBOR.Tag{tag: :bytes, value: bin}
  defp tag0_time(sec), do: %CBOR.Tag{tag: 0, value: sec |> DateTime.from_unix!(:second) |> DateTime.to_iso8601()}
  defp item_digest(tagged_item), do: tagged_item |> CBOR.encode() |> then(&:crypto.hash(:sha256, &1)) |> cbor_bytes()

  defp dpop_generator(k) do
    gen all(
          jti <- StreamData.string(:alphanumeric, min_length: 1, max_length: 10),
          path_seg <- StreamData.string(:alphanumeric, min_length: 1, max_length: 8),
          mutation <-
            StreamData.member_of([
              :valid,
              :http_scheme_htu,
              :dot_segment_htu,
              :tab_in_htu,
              :triple_slash_htu,
              :non_numeric_port_htu,
              :out_of_range_port_htu,
              :oversize_jti,
              :private_key_in_embedded_jwk,
              :wrong_use_in_embedded_jwk,
              :duplicate_claim_key,
              :non_canonical_b64_payload,
              :crit_in_header,
              :ath_non_string_without_token,
              :htm_mismatch,
              :htm_case_mismatch,
              :htu_host_mismatch,
              :htu_userinfo,
              :iat_expired,
              :iat_future,
              :jti_empty,
              :ath_mismatch,
              :wrong_typ,
              :alg_none,
              :wrong_signing_key
            ])
        ) do
      now = 1_700_000_000
      base_htu = "https://api.example.com/" <> path_seg
      base_header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => k.ec_pub_map}
      base_claims = %{"htm" => "POST", "htu" => base_htu, "iat" => now, "jti" => jti}

      {proof, opts} = mutate_dpop(mutation, k, now, path_seg, jti, base_htu, base_header, base_claims)

      %{mutation: mutation, proof: proof, opts: opts}
    end
  end

  defp mutate_dpop(:valid, k, now, _path_seg, _jti, base_htu, base_header, base_claims),
    do: {JWS.sign_compact(k.ec_pem, base_header, base_claims), [http_method: "POST", http_uri: base_htu, now: now]}

  defp mutate_dpop(:http_scheme_htu, k, now, path_seg, _jti, _base_htu, base_header, base_claims) do
    http_uri = "http://api.example.com/" <> path_seg

    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htu", http_uri)),
     [http_method: "POST", http_uri: http_uri, now: now]}
  end

  defp mutate_dpop(:dot_segment_htu, k, now, path_seg, _jti, base_htu, base_header, base_claims) do
    dot_uri = "https://api.example.com/a/../" <> path_seg

    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htu", dot_uri)),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:tab_in_htu, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htu", base_htu <> "\t")),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:triple_slash_htu, k, now, path_seg, _jti, base_htu, base_header, base_claims) do
    slash_uri = "https:///api.example.com/" <> path_seg

    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htu", slash_uri)),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:non_numeric_port_htu, k, now, path_seg, _jti, base_htu, base_header, base_claims) do
    bad_uri = "https://api.example.com:abc/" <> path_seg

    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htu", bad_uri)),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:out_of_range_port_htu, k, now, path_seg, _jti, base_htu, base_header, base_claims) do
    bad_uri = "https://api.example.com:99999/" <> path_seg

    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htu", bad_uri)),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:oversize_jti, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "jti", String.duplicate("j", 257))),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:private_key_in_embedded_jwk, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, Map.put(base_header, "jwk", k.ec_priv_map), base_claims),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:wrong_use_in_embedded_jwk, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, Map.put(base_header, "jwk", Map.put(k.ec_pub_map, "use", "enc")), base_claims),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:duplicate_claim_key, k, now, _path_seg, jti, base_htu, base_header, _base_claims) do
    h_b64 = JWS.encode64(JSON.encode!(base_header))
    p_b64 = JWS.encode64(~s({"htm":"GET","htm":"POST","htu":"#{base_htu}","iat":#{now},"jti":"#{jti}"}))
    {sign_raw_segments(k.ec_pem, "ES256", h_b64, p_b64), [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:non_canonical_b64_payload, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    h_b64 = JWS.encode64(JSON.encode!(base_header))
    nc_p = non_canonical_json_b64(JSON.encode!(base_claims))
    {sign_raw_segments(k.ec_pem, "ES256", h_b64, nc_p), [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:crit_in_header, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    h_b64 = JWS.encode64(JSON.encode!(Map.merge(base_header, %{"crit" => ["htu"], "htu" => 1})))
    p_b64 = JWS.encode64(JSON.encode!(base_claims))
    {sign_raw_segments(k.ec_pem, "ES256", h_b64, p_b64), [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:ath_non_string_without_token, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "ath", 123)),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:htm_mismatch, k, now, _path_seg, _jti, base_htu, base_header, base_claims),
    do: {JWS.sign_compact(k.ec_pem, base_header, base_claims), [http_method: "GET", http_uri: base_htu, now: now]}

  defp mutate_dpop(:htm_case_mismatch, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htm", "post")),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:htu_host_mismatch, k, now, path_seg, _jti, _base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, base_claims),
     [http_method: "POST", http_uri: "https://other.example.com/" <> path_seg, now: now]}
  end

  defp mutate_dpop(:htu_userinfo, k, now, path_seg, _jti, _base_htu, base_header, base_claims) do
    u_uri = "https://user@api.example.com/" <> path_seg

    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "htu", u_uri)),
     [http_method: "POST", http_uri: u_uri, now: now]}
  end

  defp mutate_dpop(:iat_expired, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "iat", now - 300)),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:iat_future, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "iat", now + 300)),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:jti_empty, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "jti", "")),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:ath_mismatch, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, base_header, Map.put(base_claims, "ath", "wrong_ath")),
     [http_method: "POST", http_uri: base_htu, now: now, access_token: "tok_123"]}
  end

  defp mutate_dpop(:wrong_typ, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec_pem, Map.put(base_header, "typ", "JWT"), base_claims),
     [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:alg_none, _k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    none_h = JWS.encode64(JSON.encode!(Map.put(base_header, "alg", "none")))
    p_b64 = JWS.encode64(JSON.encode!(base_claims))
    {none_h <> "." <> p_b64 <> ".", [http_method: "POST", http_uri: base_htu, now: now]}
  end

  defp mutate_dpop(:wrong_signing_key, k, now, _path_seg, _jti, base_htu, base_header, base_claims) do
    {JWS.sign_compact(k.ec2_pem, base_header, base_claims), [http_method: "POST", http_uri: base_htu, now: now]}
  end
end
