defmodule Attesto.SecurityNegativeTest do
  @moduledoc false
  # Attack/abuse cases for the verifier that are easy to forget: key-id
  # ambiguity across a rotation set, alg confusion, an unknown `crit`
  # header parameter, pathologically nested JSON, and cross-scheme
  # sender-constraint confusion.
  #
  # Every test here either installs a keystore via the app env
  # (Factory.config / RotationKeystore.install) or starts a named-singleton
  # store, so the whole module runs serially.
  use ExUnit.Case, async: false

  alias Attesto.DPoP
  alias Attesto.Key
  alias Attesto.Test.Factory
  alias Attesto.Test.RotationKeystore
  alias Attesto.Token

  @issuer "https://api.example.com/"
  @audience "https://api.example.com/"

  defp unix_now, do: DateTime.utc_now() |> DateTime.to_unix(:second)
  defp unix_in(delta) when is_integer(delta), do: unix_now() + delta

  # A complete, otherwise-valid `client` claim set. Callers override single
  # members; the principal kind ("client") and `typ` ("access") are fixed
  # so the only reason a forged token fails verify is the attack under test.
  defp client_claims(overrides \\ %{}) do
    Map.merge(
      %{
        "aud" => @audience,
        "client_id" => "oc_abc123",
        "exp" => unix_in(3600),
        "iat" => unix_now(),
        "iss" => @issuer,
        "jti" => "jti-#{System.unique_integer([:positive])}",
        "principal_kind" => "client",
        "scope" => "documents.read",
        "sub" => "oc_abc123",
        "typ" => "access"
      },
      overrides
    )
  end

  # Sign `claims` with `pem` (real RS256 signature). `:kid` may be omitted
  # entirely (hand-built kid-less token) by passing `kid: :__none__`; any
  # other value is written verbatim. `:header` merges extra protected-header
  # members (e.g. a `crit` list) on top of alg/kid.
  defp sign_rs256(pem, claims, opts \\ []) do
    jwk = Key.signing_jwk(pem)

    header =
      %{"alg" => Token.signing_alg()}
      |> maybe_put_kid(Keyword.get(opts, :kid, Key.kid(pem)))
      |> Map.merge(Keyword.get(opts, :header, %{}))

    {_protected, compact} =
      jwk
      |> JOSE.JWT.sign(header, claims)
      |> JOSE.JWS.compact()

    compact
  end

  defp maybe_put_kid(header, :__none__), do: header
  defp maybe_put_kid(header, kid), do: Map.put(header, "kid", kid)

  # Build a value nested `depth` arrays deep: [[[...0...]]].
  defp deeply_nested(depth) when is_integer(depth) and depth > 0 do
    Enum.reduce(1..depth, 0, fn _i, acc -> [acc] end)
  end

  # Hand-assemble a compact JWS from a protected header and payload without
  # a real signature, base64url-no-pad, dot-joined. Used for the alg
  # variants the verifier MUST reject before any key is consulted (HS256,
  # none): their signature segment is irrelevant to the outcome.
  defp forge_unsigned(header, payload, signature) do
    [encode_segment(header), encode_segment(payload), signature]
    |> Enum.join(".")
  end

  defp encode_segment(map) do
    map
    |> JSON.encode!()
    |> Base.url_encode64(padding: false)
  end

  describe "kid ambiguity across a rotation set" do
    setup do
      pem_a = Factory.rsa_pem()
      pem_b = Factory.rsa_pem()
      foreign = Factory.rsa_pem()

      # Rotation window: sign under A, trust both A and B.
      RotationKeystore.install(pem_a, [pem_a, pem_b])
      config = RotationKeystore.config()

      {:ok, config: config, pem_a: pem_a, pem_b: pem_b, foreign: foreign, kid_a: Key.kid(pem_a), kid_b: Key.kid(pem_b)}
    end

    test "a token whose kid names neither trusted key is :invalid_signature",
         %{config: config, pem_a: pem_a} do
      # Real signature from A, but the header advertises a kid we do not
      # hold, so candidate selection yields [] before any signature math.
      jwt = sign_rs256(pem_a, client_claims(), kid: "kid-does-not-exist")

      assert {:error, :invalid_signature} = Token.verify(config, jwt)
    end

    test "a kid-less token signed by a held key still verifies (tries all trusted keys)",
         %{config: config, pem_a: pem_a} do
      # Documented behaviour: with no `kid`, the verifier narrows to nothing
      # and tries every trusted key. Signed by A (which is trusted), it must
      # verify - the keys are all ours.
      jwt = sign_rs256(pem_a, client_claims(), kid: :__none__)

      assert {:ok, claims} = Token.verify(config, jwt)
      assert claims["sub"] == "oc_abc123"
    end

    test "a kid-less token signed by a key we hold ONLY as B also verifies",
         %{config: config, pem_b: pem_b} do
      # B is in the verification set but is not the signing key. A kid-less
      # token signed by B must still verify: the trial loop reaches B.
      jwt = sign_rs256(pem_b, client_claims(), kid: :__none__)

      assert {:ok, _claims} = Token.verify(config, jwt)
    end

    test "a kid-less token signed by a FOREIGN key is :invalid_signature",
         %{config: config, foreign: foreign} do
      # No kid, so the verifier tries every trusted key - none of which
      # signed this token. No silent wrong-key acceptance.
      jwt = sign_rs256(foreign, client_claims(), kid: :__none__)

      assert {:error, :invalid_signature} = Token.verify(config, jwt)
    end

    test "a token whose kid names B but is signed by A is :invalid_signature",
         %{config: config, pem_a: pem_a, kid_b: kid_b} do
      # kid pins the candidate to B, but the signature is A's: the single
      # selected key cannot verify it. A header kid must never override the
      # signature.
      jwt = sign_rs256(pem_a, client_claims(), kid: kid_b)

      assert {:error, :invalid_signature} = Token.verify(config, jwt)
    end
  end

  describe "alg confusion" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      {:ok, config: config, pem: pem}
    end

    test "an HS256 token (symmetric, signed with the RSA public PEM as the secret) is rejected",
         %{config: config, pem: pem} do
      # The classic RS256->HS256 confusion: an attacker who knows the public
      # key signs an HMAC with the public PEM bytes as the secret. This trusted
      # RSA key resolves to RS256, so verify_strict rejects the header.
      public_pem = Key.public_pem(pem)
      secret = JOSE.JWK.from_oct(public_pem)

      {_header, jwt} =
        secret
        |> JOSE.JWT.sign(%{"alg" => "HS256"}, client_claims())
        |> JOSE.JWS.compact()

      assert {:error, :invalid_signature} = Token.verify(config, jwt)
    end

    test "a hand-built HS256 token with an arbitrary signature segment is rejected",
         %{config: config} do
      header = %{"alg" => "HS256", "kid" => "anything"}
      jwt = forge_unsigned(header, client_claims(), "AAAA")

      assert {:error, :invalid_signature} = Token.verify(config, jwt)
    end

    test "an alg=none token (empty signature) is never accepted", %{config: config} do
      # Unsecured JWS: header.payload. with an empty signature segment.
      header = %{"alg" => "none"}
      jwt = forge_unsigned(header, client_claims(), "")

      assert {:error, reason} = Token.verify(config, jwt)
      assert reason in [:invalid_signature, :invalid_token]
    end

    test "an alg=none token claiming the real kid is still never accepted",
         %{config: config, pem: pem} do
      header = %{"alg" => "none", "kid" => Key.kid(pem)}
      jwt = forge_unsigned(header, client_claims(), "")

      assert {:error, reason} = Token.verify(config, jwt)
      assert reason in [:invalid_signature, :invalid_token]
    end
  end

  describe "unknown `crit` protected-header parameter" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      {:ok, config: config, pem: pem}
    end

    # RFC 7515 §4.1.11: a recipient that does not understand a parameter
    # named in `crit` MUST reject the JWS. This fixture's trusted key resolves
    # to RS256 and Attesto understands no extension parameters, so `crit` is
    # rejected with `:unsupported_critical_header` (JOSE itself does no `crit`
    # processing, so Attesto enforces this in `verify/3` before trusting the
    # token).
    test "a token whose protected header carries an unknown `crit` parameter is rejected",
         %{config: config, pem: pem} do
      jwt =
        sign_rs256(pem, client_claims(), header: %{"crit" => ["urn:example:unknown"], "urn:example:unknown" => true})

      assert {:error, :unsupported_critical_header} = Token.verify(config, jwt)
    end

    test "a token with `crit` naming a standard header parameter it does not process is rejected",
         %{config: config, pem: pem} do
      # `b64` (RFC 7797) is a real JOSE parameter, but attesto's verifier
      # does not negotiate it. Listing it in `crit` must force a reject.
      jwt = sign_rs256(pem, client_claims(), header: %{"crit" => ["b64"], "b64" => true})

      assert {:error, :unsupported_critical_header} = Token.verify(config, jwt)
    end
  end

  describe "deeply-nested JSON does not crash the verifier" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)
      {:ok, config: config, pem: pem}
    end

    test "a token carrying a deeply nested claim verifies without stack overflow",
         %{config: config, pem: pem} do
      claims = client_claims(%{"deep" => deeply_nested(5_000)})
      jwt = sign_rs256(pem, claims)

      # The only requirement is that the call returns a tuple rather than
      # blowing the stack or killing the process. An ok or error result is
      # equally acceptable.
      result = Token.verify(config, jwt)
      assert match?({:ok, _}, result) or match?({:error, _}, result)
    end

    test "a DPoP proof with a deeply nested claim is handled cleanly",
         %{config: _config} do
      # Forge a DPoP proof whose payload carries a deeply nested member, on
      # top of the required htm/htu/iat/jti. Sign with a real P-256 key so
      # the signature is structurally valid; the nesting must not crash
      # parse/verify.
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {_, public_map} = JOSE.JWK.to_public_map(jwk)

      header = %{"typ" => "dpop+jwt", "alg" => "ES256", "jwk" => public_map}

      payload = %{
        "htm" => "POST",
        "htu" => "https://api.example.com/oauth/token",
        "iat" => unix_now(),
        "jti" => "jti-#{System.unique_integer([:positive])}",
        "deep" => deeply_nested(5_000)
      }

      {_, proof} = jwk |> JOSE.JWT.sign(header, payload) |> JOSE.JWS.compact()

      result =
        DPoP.verify_proof(proof,
          http_method: "POST",
          http_uri: "https://api.example.com/oauth/token",
          now: unix_now()
        )

      assert match?({:ok, _}, result) or match?({:error, _}, result)
    end
  end

  describe "cnf cross-presentation guard" do
    setup do
      pem = Factory.rsa_pem()
      config = Factory.config(pem)

      # A real DPoP key + its thumbprint, and a real cert thumbprint, so the
      # bound values are canonical shapes the verifier accepts structurally.
      {_proof, jkt} = Factory.dpop_proof()
      x5t = Attesto.Thumbprint.of(:crypto.strong_rand_bytes(64))

      {:ok, config: config, jkt: jkt, x5t: x5t}
    end

    test "a DPoP-bound token verified with an mTLS thumbprint opt is :mtls_cert_unexpected",
         %{config: config, jkt: jkt, x5t: x5t} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
                 dpop_jkt: jkt
               )

      # Cross-scheme: the token carries cnf.jkt (DPoP) but the verifier is
      # handed an mTLS thumbprint. The cross-scheme option must be flatly
      # rejected, taking precedence over a missing DPoP proof.
      assert {:error, :mtls_cert_unexpected} =
               Token.verify(config, jwt, mtls_cert_thumbprint: x5t)
    end

    test "a DPoP-bound token rejects the mTLS opt even when the matching DPoP opt is ALSO present",
         %{config: config, jkt: jkt, x5t: x5t} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
                 dpop_jkt: jkt
               )

      # Even with the correct DPoP proof supplied, the presence of a
      # cross-scheme mTLS opt poisons the verification.
      assert {:error, :mtls_cert_unexpected} =
               Token.verify(config, jwt, dpop_jkt: jkt, mtls_cert_thumbprint: x5t)
    end

    test "an mTLS-bound token verified with a DPoP thumbprint opt is :dpop_proof_unexpected",
         %{config: config, jkt: jkt, x5t: x5t} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
                 mtls_cert_thumbprint: x5t
               )

      # Mirror image: the token carries cnf.x5t#S256 (mTLS) but the verifier
      # is handed a DPoP jkt. Reject as :dpop_proof_unexpected.
      assert {:error, :dpop_proof_unexpected} =
               Token.verify(config, jwt, dpop_jkt: jkt)
    end

    test "an mTLS-bound token rejects the DPoP opt even alongside the matching mTLS opt",
         %{config: config, jkt: jkt, x5t: x5t} do
      assert {:ok, %{access_token: jwt}} =
               Token.mint(
                 config,
                 %{kind: "client", sub: "oc_abc123", scopes: ["documents.read"], claims: %{"client_id" => "oc_abc123"}},
                 mtls_cert_thumbprint: x5t
               )

      assert {:error, :dpop_proof_unexpected} =
               Token.verify(config, jwt, mtls_cert_thumbprint: x5t, dpop_jkt: jkt)
    end
  end
end
