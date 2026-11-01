"""Reference Python primitives for the Attesto cross-language parity tests.

Driven in-process from the BEAM via `erlang_python` (the `:py` NIF), the
same bridge approach the surrounding test suite uses elsewhere. Each
function takes plain bindings (the Elixir side passes binaries and maps,
which arrive as Python `bytes`/`dict`) and returns plain data (str / int /
dict / tuple) so the result decodes straight back to Elixir terms.

Two independent reference implementations underpin the JWT-verify leg so
parity is not merely round-tripping one library's own canonicalisation:

  - `joserfc` is the high-level RFC stack (RS256 JWT verify, EC keys,
    RFC 7638 thumbprints, ES256 DPoP proofs).
  - `cryptography` is used directly (raw RSA-PKCS1v15-SHA256 verify plus a
    hand-rolled JWT decode) as a second, decode-independent check.

Required importable packages in the active interpreter: `joserfc`,
`cryptography`.
"""

import base64
import hashlib
import json
import os

from urllib.parse import urlsplit
from joserfc import jwe as jose_jwe
from joserfc import jws as jose_jws
from joserfc import jwt as jose_jwt
from joserfc.jwk import ECKey, RSAKey, import_key

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _s(v):
    """`erlang_python` hands Elixir binaries over as Python `bytes`. The
    reference libraries want `str` keys/values (and the verifiers compare
    `iss`/`aud`, which are `str`). Normalise every value crossing the
    boundary back to `str`, recursing into dict keys/values so a
    round-tripped JWK re-imports cleanly."""
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8")
    if isinstance(v, dict):
        return {_s(k): _s(val) for k, val in v.items()}
    return v


def _b64url_nopad(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment):
    segment = _s(segment)
    padding_len = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding_len)


def generate_pkce_pair():
    """Generate a fresh PKCE `code_verifier` (RFC 7636 §4.1: 43..128
    unreserved characters) and its `S256` `code_challenge`
    (base64url(SHA-256(verifier)), no padding), exactly as a real client
    library would. Returns `(verifier, challenge)` as plain str."""
    verifier = _b64url_nopad(os.urandom(32))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = _b64url_nopad(digest)
    return (verifier, challenge)


def compute_oidc_hash(value):
    """Compute an OIDC Core §3.1.3.6 / §3.3.2.11 hash claim (`at_hash`,
    `c_hash`) the way the spec prescribes for an RS256 ID Token: hash the
    ASCII octets of `value` with SHA-256 (the hash of the token's signing
    algorithm), take the left-most half of that digest (128 bits / 16 bytes
    for SHA-256), and base64url-encode without padding. Returns plain str.

    This shares no code with Attesto's Elixir `hash_claim/1`, so agreement
    is a genuine cross-implementation check of the half-digest construction
    (the off-by-one trap is taking the full digest, or the wrong half)."""
    digest = hashlib.sha256(_s(value).encode("ascii")).digest()
    left_most_half = digest[: len(digest) // 2]
    return _b64url_nopad(left_most_half)


def verify_id_token_c_hash(code, expected_c_hash):
    """Independently verify the `c_hash` claim of an Attesto-minted ID Token
    (OIDC Core §3.3.2.11). `code` is the authorization code the ID Token was
    bound to; `expected_c_hash` is the `c_hash` claim Attesto emitted.

    Recomputes `c_hash` from `code` here in Python via `compute_oidc_hash`
    and asserts it matches what Attesto produced, mirroring the `at_hash`
    parity assertion in cross_language_parity_test.exs. Raises `ValueError`
    on a mismatch (surfacing to Elixir as a test error); returns `True` on
    agreement so the Elixir side can assert a plain truthy result."""
    computed = compute_oidc_hash(code)
    expected = _s(expected_c_hash)
    if computed != expected:
        raise ValueError("c_hash mismatch: %r != %r" % (computed, expected))
    return True


def joserfc_verify_rs256(token, public_pem):
    """Verify an RS256 JWT with joserfc against an RSA public PEM and
    return the decoded claims as a plain dict."""
    key = RSAKey.import_key(_s(public_pem))
    decoded = jose_jwt.decode(_s(token), key, algorithms=["RS256"])
    return dict(decoded.claims)


def build_rs256_jwt(claims, private_pem, typ="JWT"):
    """Sign a compact RS256 JWT with joserfc using the supplied RSA private
    PEM. Used for inbound parity: Python emits the wire object, Attesto
    verifies it. `typ=None` omits the header member."""
    key = RSAKey.import_key(_s(private_pem))
    header = {"alg": "RS256", "kid": key.thumbprint()}
    typ = _s(typ)
    if typ is not None:
        header["typ"] = typ
    return jose_jwt.encode(header, _s(claims), key, algorithms=["RS256"])


def cryptography_verify_rs256(token, public_pem, issuer, audience):
    """Verify the same RS256 JWT with `cryptography` directly: split the
    compact JWS, verify the RSA-PKCS1v15-SHA256 signature over the signing
    input, decode the claims by hand, and enforce `iss`/`aud`. This shares
    no JWT-decode code with joserfc, so agreement between the two is a
    genuine cross-implementation check rather than one library validating
    its own output. Raises on a bad signature or an `iss`/`aud` mismatch
    (surfacing to Elixir as a test error). Returns the claims dict."""
    token = _s(token)
    header_b64, payload_b64, signature_b64 = token.split(".")
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    signature = _b64url_decode(signature_b64)

    public_key = serialization.load_pem_public_key(_s(public_pem).encode("ascii"))
    # Raises cryptography.exceptions.InvalidSignature on a forged token.
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    claims = json.loads(_b64url_decode(payload_b64))

    if claims.get("iss") != _s(issuer):
        raise ValueError("iss mismatch: %r != %r" % (claims.get("iss"), _s(issuer)))

    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if _s(audience) not in auds:
        raise ValueError("aud mismatch: %r not in %r" % (_s(audience), auds))

    return claims


def joserfc_jwk_thumbprint(jwk_dict):
    """RFC 7638 SHA-256 thumbprint of an EC public JWK, as joserfc computes
    it. `jwk_dict` carries only public members (`kty`/`crv`/`x`/`y`)."""
    key = ECKey.import_key(_s(jwk_dict))
    return key.thumbprint()


def generate_ec256_public_jwk():
    """Generate a fresh EC P-256 key and return ONLY its public JWK members
    (`kty`/`crv`/`x`/`y`) as a plain dict."""
    key = ECKey.generate_key(crv="P-256")
    return dict(key.as_dict(private=False))


def build_es256_dpop_proof(htm, htu, iat, jti):
    """Generate a fresh EC P-256 key in Python and sign a DPoP proof JWS
    (RFC 9449 §4) with it: header carries `typ: dpop+jwt`, `alg: ES256`, and
    the embedded PUBLIC jwk; payload carries `htm`/`htu`/`iat`/`jti`.

    Returns `(proof_compact, public_jwk_dict, thumbprint)` so the Elixir
    side can feed the proof to Attesto and assert the verified `jkt` equals
    Python's own RFC 7638 thumbprint of the signing key."""
    key = ECKey.generate_key(crv="P-256")
    public_jwk = dict(key.as_dict(private=False))

    header = {
        "alg": "ES256",
        "jwk": public_jwk,
        "typ": "dpop+jwt",
    }
    claims = {
        "htm": _s(htm),
        "htu": _s(htu),
        "iat": int(iat),
        "jti": _s(jti),
    }
    proof = jose_jwt.encode(header, claims, key, algorithms=["ES256"])
    return (proof, public_jwk, key.thumbprint())


# ── Differential fuzzing oracle helpers ───────────────────────────────────


def _deep_str(v):
    """Recursively decode UTF-8 bytes in dicts/lists/tuples into str."""
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8")
    if isinstance(v, dict):
        return {_deep_str(k): _deep_str(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_deep_str(item) for item in v]
    if isinstance(v, tuple):
        return tuple(_deep_str(item) for item in v)
    return v


_JWK_CACHE = {}


def _import_any_jwk(jwk_dict):
    d = _deep_str(jwk_dict)
    cache_key = json.dumps(d, sort_keys=True)
    cached = _JWK_CACHE.get(cache_key)
    if cached is not None:
        return cached
    key = import_key(d)
    if len(_JWK_CACHE) < 128:
        _JWK_CACHE[cache_key] = key
    return key


def fuzz_verify_jws(token, jwk_dict, algorithms):
    """Oracle for JWS/JWT compact verification using joserfc."""
    try:
        from joserfc import jws as jose_jws

        token_str = _deep_str(token)
        algs = [_deep_str(a) for a in algorithms]
        key = _import_any_jwk(jwk_dict)
        obj = jose_jws.deserialize_compact(token_str, key, algorithms=algs)
        claims = json.loads(obj.payload.decode("utf-8"))
        if not isinstance(claims, dict):
            return {
                "ok": False,
                "error": "DecodeError",
                "message": "payload is not a JSON object",
            }
        return {
            "ok": True,
            "header": _deep_str(dict(obj.headers())),
            "claims": _deep_str(claims),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc),
        }


def fuzz_decrypt_jwe(compact, private_jwk_dict, algs, encs):
    """Oracle for compact JWE decryption using joserfc."""
    try:
        compact_str = _deep_str(compact)
        key = _import_any_jwk(private_jwk_dict)
        obj = jose_jwe.decrypt_compact(compact_str, key)
        hdr = _deep_str(dict(obj.headers()))
        if hdr.get("alg") not in [_deep_str(a) for a in algs]:
            return {"ok": False, "error": "UnsupportedAlgorithmError", "message": str(hdr.get("alg"))}
        if hdr.get("enc") not in [_deep_str(e) for e in encs]:
            return {"ok": False, "error": "UnsupportedAlgorithmError", "message": str(hdr.get("enc"))}
        return {
            "ok": True,
            "plaintext_b64": _b64url_nopad(obj.plaintext),
            "header": hdr,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc),
        }


def fuzz_encrypt_jwe(public_jwk_dict, plaintext_b64, protected_header):
    """Produce a compact JWE via joserfc.jwe.encrypt_compact."""
    key = _import_any_jwk(public_jwk_dict)
    header = _deep_str(protected_header)
    plaintext = _b64url_decode(plaintext_b64)
    algs = [header.get("alg", "ECDH-ES"), header.get("enc", "A128GCM"), "DEF"]
    return jose_jwe.encrypt_compact(header, plaintext, key, algorithms=algs)


def sign_ps256_custom_salt(signing_input, private_pem, salt_len):
    """Sign ASCII signing_input with RSA-PSS SHA-256 using an explicit salt_len."""
    priv = serialization.load_pem_private_key(_deep_str(private_pem).encode("ascii"), password=None)
    sig = priv.sign(
        _deep_str(signing_input).encode("ascii"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=int(salt_len)),
        hashes.SHA256(),
    )
    return _b64url_nopad(sig)


def _sd_hash(data_ascii, sd_alg):
    alg_map = {
        "sha-256": hashlib.sha256,
        "sha-384": hashlib.sha384,
        "sha-512": hashlib.sha512,
    }
    if sd_alg not in alg_map:
        raise ValueError(f"unsupported _sd_alg: {sd_alg}")
    return _b64url_nopad(alg_map[sd_alg](data_ascii.encode("ascii")).digest())


def fuzz_decode_disclosures(disclosures, sd_alg="sha-256"):
    """Independent Python RFC 9901 disclosure decoder."""
    try:
        sd_alg_str = _deep_str(sd_alg)
        if sd_alg_str not in ("sha-256", "sha-384", "sha-512"):
            return {"ok": False, "error": "UnsupportedSdAlg", "message": sd_alg_str}
        result = {}
        for d in disclosures:
            d_str = _deep_str(d)
            if "=" in d_str:
                return {"ok": False, "error": "InvalidDisclosure", "message": "padded base64url"}
            raw = _b64url_decode(d_str)
            arr = json.loads(raw.decode("utf-8"))
            if not isinstance(arr, list) or len(arr) not in (2, 3):
                return {"ok": False, "error": "InvalidDisclosure", "message": "bad array length"}
            if not isinstance(arr[0], str):
                return {"ok": False, "error": "InvalidDisclosure", "message": "salt not str"}
            if len(arr) == 3:
                if not isinstance(arr[1], str):
                    return {"ok": False, "error": "InvalidDisclosure", "message": "name not str"}
                if arr[1] in ("_sd", "_sd_alg", "..."):
                    return {"ok": False, "error": "ReservedClaimName", "message": arr[1]}
            digest = _sd_hash(d_str, sd_alg_str)
            if digest in result:
                return {"ok": False, "error": "DuplicateDigest", "message": digest}
            result[digest] = _deep_str(arr)
        return {"ok": True, "disclosures": result}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "message": str(exc)}


def fuzz_verify_sd_jwt(combined, issuer_jwk_dict, algorithms, holder_jwk_dict=None, kb_opts=None):
    """Independent Python RFC 9901 SD-JWT presentation verifier using joserfc."""
    try:
        from joserfc import jws as jose_jws

        combined_str = _deep_str(combined)
        segments = combined_str.split("~")
        if len(segments) < 2 or segments[0] == "":
            return {"ok": False, "error": "MalformedSdJwt", "message": "missing separator"}

        issuer_jwt = segments[0]
        disclosures = segments[1:-1]
        kb_jwt = segments[-1] if segments[-1] != "" else None
        if any(d == "" for d in disclosures):
            return {"ok": False, "error": "MalformedSdJwt", "message": "empty disclosure segment"}

        algs = [_deep_str(a) for a in algorithms]
        issuer_key = _import_any_jwk(issuer_jwk_dict)
        jws_obj = jose_jws.deserialize_compact(issuer_jwt, issuer_key, algorithms=algs)
        payload = json.loads(jws_obj.payload.decode("utf-8"))
        if not isinstance(payload, dict):
            return {"ok": False, "error": "InvalidPayload", "message": "payload not dict"}

        sd_alg = payload.get("_sd_alg", "sha-256")
        if not isinstance(sd_alg, str) or sd_alg not in ("sha-256", "sha-384", "sha-512"):
            return {"ok": False, "error": "UnsupportedSdAlg", "message": str(sd_alg)}

        dec = fuzz_decode_disclosures(disclosures, sd_alg)
        if not dec["ok"]:
            return dec
        by_digest = dec["disclosures"]
        used = set()
        referenced = set()

        def resolve_val(val, top=False):
            if isinstance(val, dict):
                obj = dict(val)
                sd_list = obj.pop("_sd", [])
                if top:
                    obj.pop("_sd_alg", None)
                if not isinstance(sd_list, list):
                    raise ValueError("_sd is not a list")
                disclosed_props = {}
                for d in sd_list:
                    if not isinstance(d, str):
                        raise ValueError("_sd digest not string")
                    if d in referenced:
                        raise ValueError("duplicate digest reference")
                    referenced.add(d)
                    if d in by_digest:
                        arr = by_digest[d]
                        if len(arr) != 3:
                            raise ValueError("array disclosure in _sd")
                        _, name, dval = arr
                        if d in used or name in disclosed_props:
                            raise ValueError("duplicate disclosure use")
                        used.add(d)
                        disclosed_props[name] = resolve_val(dval, False)
                out = {}
                for k, v in obj.items():
                    if k in ("_sd", "_sd_alg", "..."):
                        raise ValueError(f"reserved claim name {k}")
                    out[k] = resolve_val(v, False)
                for k, v in disclosed_props.items():
                    if k in out:
                        raise ValueError(f"disclosed claim {k} collides with cleartext")
                    out[k] = v
                return out
            elif isinstance(val, list):
                out_list = []
                for elem in val:
                    if isinstance(elem, dict) and list(elem.keys()) == ["..."]:
                        d = elem["..."]
                        if not isinstance(d, str):
                            raise ValueError("array digest not string")
                        if d in referenced:
                            raise ValueError("duplicate digest reference")
                        referenced.add(d)
                        if d in by_digest:
                            arr = by_digest[d]
                            if len(arr) != 2:
                                raise ValueError("object disclosure in array")
                            used.add(d)
                            out_list.append(resolve_val(arr[1], False))
                    else:
                        out_list.append(resolve_val(elem, False))
                return out_list
            else:
                return val

        claims = resolve_val(payload, top=True)
        if len(used) != len(by_digest):
            return {"ok": False, "error": "UnusedDisclosure", "message": "unused disclosure"}

        kb_opts = _deep_str(kb_opts) if kb_opts else None
        if kb_opts and kb_opts.get("require_kb"):
            if not kb_jwt or not holder_jwk_dict:
                return {"ok": False, "error": "MissingKbJwt", "message": "missing kb_jwt"}
            holder_key = _import_any_jwk(holder_jwk_dict)
            kb_alg = kb_opts.get("alg", "ES256")
            kb_obj = jose_jws.deserialize_compact(kb_jwt, holder_key, algorithms=[kb_alg])
            kb_hdr = dict(kb_obj.headers())
            if kb_hdr.get("typ") != "kb+jwt":
                return {"ok": False, "error": "InvalidKbTyp", "message": str(kb_hdr.get("typ"))}
            kb_claims = json.loads(kb_obj.payload.decode("utf-8"))
            if kb_claims.get("nonce") != kb_opts.get("nonce"):
                return {"ok": False, "error": "InvalidKbNonce", "message": "kb nonce mismatch"}
            if kb_claims.get("aud") != kb_opts.get("audience"):
                return {"ok": False, "error": "InvalidKbAud", "message": "kb aud mismatch"}
            expected_sd_hash = _sd_hash("~".join([issuer_jwt] + disclosures + [""]), sd_alg)
            if kb_claims.get("sd_hash") != expected_sd_hash:
                return {"ok": False, "error": "InvalidKbSdHash", "message": "sd_hash mismatch"}

        return {"ok": True, "claims": _deep_str(claims)}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "message": str(exc)}



def fuzz_verify_dpop(proof, opts):
    """Independent Python RFC 9449 DPoP proof verifier powered by joserfc and urllib.parse."""
    try:
        from urllib.parse import urlsplit
        from joserfc import jws as jose_jws

        opts = _deep_str(opts)
        proof_str = _deep_str(proof)
        parts = proof_str.split(".")
        if len(parts) != 3:
            return {"ok": False, "error": "MalformedCompact", "message": "expected 3 segments"}

        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        if not isinstance(header, dict):
            return {"ok": False, "error": "InvalidHeader", "message": "header not object"}
        if header.get("typ") != "dpop+jwt":
            return {"ok": False, "error": "InvalidTyp", "message": str(header.get("typ"))}

        alg = header.get("alg")
        allowed_algs = opts.get(
            "algorithms",
            ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"],
        )
        if not isinstance(alg, str) or alg not in allowed_algs:
            return {"ok": False, "error": "InvalidAlg", "message": str(alg)}

        jwk_map = header.get("jwk")
        if not isinstance(jwk_map, dict) or not jwk_map:
            return {"ok": False, "error": "MissingJwk", "message": "missing jwk"}

        key = _import_any_jwk(jwk_map)
        obj = jose_jws.deserialize_compact(proof_str, key, algorithms=[alg])
        claims = json.loads(obj.payload.decode("utf-8"))
        if not isinstance(claims, dict):
            return {"ok": False, "error": "InvalidPayload", "message": "claims not object"}

        if claims.get("htm") != opts.get("http_method"):
            return {"ok": False, "error": "InvalidHtm", "message": str(claims.get("htm"))}

        htu = claims.get("htu")
        expected_htu = opts.get("http_uri")
        if not isinstance(htu, str) or not isinstance(expected_htu, str):
            return {"ok": False, "error": "InvalidHtu", "message": "htu not str"}

        u1 = urlsplit(htu)
        u2 = urlsplit(expected_htu)
        if u1.scheme.lower() not in ("http", "https") or not u1.hostname:
            return {"ok": False, "error": "InvalidHtu", "message": "bad scheme/host"}
        if u1.username is not None or u1.password is not None:
            return {"ok": False, "error": "InvalidHtu", "message": "userinfo present"}
        p1 = None if (u1.scheme.lower() == "https" and u1.port == 443) else u1.port
        p2 = None if (u2.scheme.lower() == "https" and u2.port == 443) else u2.port
        path1 = u1.path or "/"
        path2 = u2.path or "/"
        if (u1.scheme.lower(), u1.hostname.lower(), p1, path1) != (
            u2.scheme.lower(),
            u2.hostname.lower(),
            p2,
            path2,
        ):
            return {"ok": False, "error": "InvalidHtu", "message": "htu mismatch"}

        iat = claims.get("iat")
        if isinstance(iat, bool) or not isinstance(iat, int) or iat < 0:
            return {"ok": False, "error": "InvalidIat", "message": str(iat)}
        now = int(opts.get("now", 0))
        max_age = int(opts.get("max_age_seconds", 60))
        if iat > now + 60:
            return {"ok": False, "error": "FutureIat", "message": str(iat)}
        if iat < now - max_age:
            return {"ok": False, "error": "ExpiredIat", "message": str(iat)}

        jti = claims.get("jti")
        if not isinstance(jti, str) or jti == "":
            return {"ok": False, "error": "InvalidJti", "message": str(jti)}

        access_token = opts.get("access_token")
        ath = claims.get("ath")
        if access_token is not None:
            if not isinstance(ath, str):
                return {"ok": False, "error": "MissingAth", "message": "missing ath"}
            expected_ath = _b64url_nopad(hashlib.sha256(access_token.encode("ascii")).digest())
            if ath != expected_ath:
                return {"ok": False, "error": "InvalidAth", "message": "ath mismatch"}

        expected_nonce = opts.get("expected_nonce")
        if expected_nonce is not None and claims.get("nonce") != expected_nonce:
            return {"ok": False, "error": "UseDpopNonce", "message": "nonce mismatch"}

        return {
            "ok": True,
            "jkt": key.thumbprint(),
            "jti": jti,
            "htm": claims["htm"],
            "htu": claims["htu"],
            "iat": iat,
            "ath": ath,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc),
        }

