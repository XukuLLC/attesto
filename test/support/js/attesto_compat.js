// JS JOSE reference for attesto cross-language parity tests (test-support only).
// jose v5 is ESM-only, so it's loaded via dynamic import inside each async fn;
// the `nodejs` Elixir bridge loads this CommonJS module and calls these exports.
let josePromise;
function jose() {
  if (!josePromise) josePromise = import("jose");
  return josePromise;
}

let sdJwtPromise;
function sdJwtLibraries() {
  if (!sdJwtPromise) {
    sdJwtPromise = Promise.all([
      import("@sd-jwt/sd-jwt-vc"),
      import("@sd-jwt/core"),
    ]).then(([vc, core]) => ({ vc, core }));
  }
  return sdJwtPromise;
}

function sdHasher(data, alg) {
  const nodeAlg = { "sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512" }[alg];
  if (!nodeAlg) throw new TypeError(`unsupported SD-JWT hash algorithm ${alg}`);
  return new Uint8Array(crypto.createHash(nodeAlg).update(Buffer.from(data)).digest());
}

async function es256Verifier(publicJwk) {
  const j = await jose();
  const key = await j.importJWK(publicJwk, "ES256");

  return async (data, signature) => {
    try {
      await j.compactVerify(`${data}.${signature}`, key, {
        algorithms: ["ES256"],
      });
      return true;
    } catch (_error) {
      return false;
    }
  };
}

// Verify an SD-JWT VC presentation, including issuer signature, Disclosures,
// and its holder-signed KB-JWT. sd-jwt-js reconstructs the disclosed payload;
// its KB verifier receives the reconstructed cnf key and jose verifies ES256.
async function verifySdJwtVc(
  presentation,
  issuerPublicJwk,
  nonce,
  audience,
  currentDate,
) {
  const j = await jose();
  const { vc, core } = await sdJwtLibraries();
  if (typeof core.decodeSdJwt !== "function")
    throw new Error("@sd-jwt/core did not load");

  const verifier = await es256Verifier(issuerPublicJwk);
  const kbVerifier = async (data, signature, payload) => {
    const holderJwk = payload && payload.cnf && payload.cnf.jwk;
    if (!holderJwk) throw new Error("SD-JWT VC is missing cnf.jwk");
    const holderKey = await j.importJWK(holderJwk, "ES256");

    try {
      await j.compactVerify(`${data}.${signature}`, holderKey, {
        algorithms: ["ES256"],
      });
      return true;
    } catch (_error) {
      return false;
    }
  };

  const instance = new vc.SDJwtVcInstance({
    verifier,
    kbVerifier,
    hasher: sdHasher,
    hashAlg: "sha-256",
  });

  const verified = await instance.verify(presentation, {
    currentDate,
    skewSeconds: 60,
    keyBindingNonce: nonce,
    disableStatusVerification: true,
  });

  if (!verified.header || !["vc+sd-jwt", "dc+sd-jwt"].includes(verified.header.typ))
    throw new Error("unexpected SD-JWT VC typ");
  if (verified.header.alg !== "ES256")
    throw new Error("unexpected SD-JWT VC algorithm");
  if (!verified.payload.iss || !verified.payload.vct)
    throw new Error("SD-JWT VC is missing iss or vct");
  if (!verified.kb || verified.kb.payload.aud !== audience)
    throw new Error("KB-JWT audience mismatch");

  return {
    claims: verified.payload,
    header: verified.header,
    keyBinding: verified.kb.payload,
  };
}
module.exports.verifySdJwtVc = verifySdJwtVc;

// Reverse leg: sd-jwt-js issues a dc+sd-jwt credential and Attesto verifies
// it. The library owns the Disclosure construction; Node crypto supplies the
// ES256 signer callback expected by @sd-jwt/core.
async function issueSdJwtVc(claims, disclosable, issuerPrivateJwk) {
  const j = await jose();
  const { vc, core } = await sdJwtLibraries();
  if (typeof core.decodeSdJwt !== "function")
    throw new Error("@sd-jwt/core did not load");

  const privateKey = await j.importJWK(issuerPrivateJwk, "ES256");
  const signer = (data) =>
    crypto
      .sign("sha256", Buffer.from(data), {
        key: privateKey,
        dsaEncoding: "ieee-p1363",
      })
      .toString("base64url");

  const instance = new vc.SDJwtVcInstance({
    signer,
    signAlg: "ES256",
    hasher: sdHasher,
    hashAlg: "sha-256",
    saltGenerator: (length) => crypto.randomBytes(length).toString("base64url"),
  });

  return await instance.issue(claims, { _sd: disclosable });
}
module.exports.issueSdJwtVc = issueSdJwtVc;

// @auth0/mdl's public parser consumes a DeviceResponse. Attesto issues the
// contained bare IssuerSigned structure, so wrap its decoded contents in that
// reference form, then use mdl's IssuerAuth and IssuerSignedItem
// verifiers against the caller-supplied issuer public key.
async function verifyMdoc(issuerSignedBase64url, issuerPublicJwk) {
  const mdl = require("@auth0/mdl");
  const { cborDecode, cborEncode } = require("@auth0/mdl/lib/cbor");
  const IssuerAuth = require("@auth0/mdl/lib/mdoc/model/IssuerAuth").default;
  const issuerSigned = cborDecode(Buffer.from(issuerSignedBase64url, "base64url"));

  if (!(issuerSigned instanceof Map))
    throw new TypeError("IssuerSigned must decode to a CBOR map");
  const rawIssuerAuth = issuerSigned.get("issuerAuth");
  if (!Array.isArray(rawIssuerAuth))
    throw new TypeError("IssuerSigned is missing issuerAuth");

  const docType = new IssuerAuth(...rawIssuerAuth).decodedPayload.docType;
  const deviceResponse = cborEncode(
    new Map([
      ["version", "1.0"],
      [
        "documents",
        [
          new Map([
            ["docType", docType],
            ["issuerSigned", issuerSigned],
          ]),
        ],
      ],
      ["status", 0],
    ]),
  );

  const parsed = mdl.parse(deviceResponse);
  const document = parsed.documents[0];
  const issuerAuth = document.issuerSigned.issuerAuth;
  const j = await jose();
  const issuerKey = await j.importJWK(issuerPublicJwk, issuerAuth.algName);

  if (!(await issuerAuth.verify(issuerKey)))
    throw new Error("mdoc issuer signature verification failed");

  const namespaces = {};
  for (const namespace of document.issuerSignedNameSpaces) {
    const items = document.issuerSigned.nameSpaces[namespace];
    const checks = await Promise.all(
      items.map((item) => item.isValid(namespace, issuerAuth)),
    );
    if (checks.some((valid) => !valid))
      throw new Error(`mdoc digest verification failed for ${namespace}`);
    namespaces[namespace] = document.getIssuerNameSpace(namespace);
  }

  return { docType: document.docType, namespaces };
}
module.exports.verifyMdoc = verifyMdoc;

// Verify OID4VCI jwt_vc_json and return exactly the issuer-signed vc claim.
async function verifyJwtVc(token, issuerPublicJwk) {
  const j = await jose();
  const key = await j.importJWK(issuerPublicJwk, "ES256");
  const { payload, protectedHeader } = await j.jwtVerify(token, key, {
    algorithms: ["ES256"],
    typ: "JWT",
  });
  if (!payload.vc || typeof payload.vc !== "object")
    throw new Error("jwt_vc_json is missing vc");
  return { header: protectedHeader, vc: payload.vc };
}
module.exports.verifyJwtVc = verifyJwtVc;

// Verify a statuslist+jwt, inflate its zlib-compressed list, and read the
// least-significant-first status field at idx (draft Token Status List wire).
async function verifyStatusList(token, issuerPublicJwk, idx) {
  const j = await jose();
  const key = await j.importJWK(issuerPublicJwk, "ES256");
  const { payload, protectedHeader } = await j.jwtVerify(token, key, {
    algorithms: ["ES256"],
    typ: "statuslist+jwt",
  });
  const statusList = payload.status_list;
  if (!statusList || ![1, 2, 4, 8].includes(statusList.bits))
    throw new Error("invalid status_list claim");

  const packed = require("zlib").inflateSync(
    Buffer.from(statusList.lst, "base64url"),
  );
  const perByte = 8 / statusList.bits;
  if (!Number.isInteger(idx) || idx < 0 || idx >= packed.length * perByte)
    throw new RangeError("status index is out of range");
  const offset = (idx % perByte) * statusList.bits;
  const status = (packed[Math.floor(idx / perByte)] >> offset) &
    ((1 << statusList.bits) - 1);

  return {
    bits: statusList.bits,
    header: protectedHeader,
    status,
    sub: payload.sub,
  };
}
module.exports.verifyStatusList = verifyStatusList;

// Verify a holder-signed OID4VCI proof or KB-JWT with jose and return its
// claims. When the proof embeds a jwk, also prove it names the supplied key.
async function verifyHolderProof(token, holderPublicJwk, typ, expectedClaims) {
  const j = await jose();
  const key = await j.importJWK(holderPublicJwk, "ES256");
  const { payload, protectedHeader } = await j.jwtVerify(token, key, {
    algorithms: ["ES256"],
    typ,
  });

  if (protectedHeader.jwk) {
    const [embeddedJkt, expectedJkt] = await Promise.all([
      j.calculateJwkThumbprint(protectedHeader.jwk, "sha256"),
      j.calculateJwkThumbprint(holderPublicJwk, "sha256"),
    ]);
    if (embeddedJkt !== expectedJkt)
      throw new Error("holder proof embedded jwk mismatch");
  }

  for (const [claim, expected] of Object.entries(expectedClaims || {})) {
    if (JSON.stringify(payload[claim]) !== JSON.stringify(expected))
      throw new Error(`holder proof ${claim} mismatch`);
  }

  return { header: protectedHeader, payload };
}
module.exports.verifyHolderProof = verifyHolderProof;

// Verify a compact JWT with a PEM public key + alg. Returns {header, payload}.
async function verifyJwt(token, publicPem, alg) {
  const j = await jose();
  const key = await j.importSPKI(publicPem, alg);
  const { payload, protectedHeader } = await j.jwtVerify(token, key, {
    algorithms: [alg],
  });
  return { header: protectedHeader, payload };
}

// Node's native EdDSA verifier supplies independent RFC 8032 parity for exact
// RFC 9864 identifiers that jose v5 does not yet accept (notably Ed448).
function verifyEdwardsJwt(token, publicPem) {
  const parts = token.split(".");
  if (parts.length !== 3)
    throw new TypeError("compact JWT must have three parts");

  const [headerB64, payloadB64, signatureB64] = parts;
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
  const signature = Buffer.from(signatureB64, "base64url");
  const key = crypto.createPublicKey(publicPem);

  if (!crypto.verify(null, signingInput, key, signature)) {
    throw new Error("Edwards JWT signature verification failed");
  }

  return {
    header: JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")),
  };
}

// RFC 7638 JWK thumbprint (SHA-256, base64url, no pad).
async function jwkThumbprint(jwk) {
  const j = await jose();
  return await j.calculateJwkThumbprint(jwk, "sha256");
}

// Sign a JWT (inbound parity: JS issues -> Attesto verifies).
async function signJwt(claims, privatePem, alg, typ) {
  const j = await jose();
  const key = await j.importPKCS8(privatePem, alg);
  return await new j.SignJWT(claims)
    .setProtectedHeader({ alg, typ: typ || "JWT" })
    .sign(key);
}

Object.assign(module.exports, { verifyJwt, jwkThumbprint, signJwt });
module.exports.verifyEdwardsJwt = verifyEdwardsJwt;

// Availability probe: resolves to "pong" iff jose and every wallet reference
// dependency load. This keeps parity tests skipped, rather than failed, when a
// checkout has not run npm install after package.json changes.
async function ping() {
  const j = await jose();
  const { vc, core } = await sdJwtLibraries();
  const mdl = require("@auth0/mdl");
  return typeof j.jwtVerify === "function" &&
    typeof vc.SDJwtVcInstance === "function" &&
    typeof core.decodeSdJwt === "function" &&
    typeof mdl.parse === "function"
    ? "pong"
    : "missing-wallet-dependency";
}
module.exports.ping = ping;

// RFC 8705 §3.1 x5t#S256 = base64url(SHA-256(DER cert)). jose has no cert
// thumbprint; use node crypto directly over the DER bytes (passed base64).
const crypto = require("crypto");
function x5tS256(derBase64) {
  const der = Buffer.from(derBase64, "base64");
  return crypto.createHash("sha256").update(der).digest("base64url");
}
module.exports.x5tS256 = x5tS256;

// OIDC Core §3.1.3.6 / §3.3.2.11 hash-claim reference.
function oidcHash(value, alg, crv) {
  let hash;

  if (["RS256", "PS256", "ES256"].includes(alg)) {
    hash = crypto.createHash("sha256");
  } else if (alg === "ES384") {
    hash = crypto.createHash("sha384");
  } else if (alg === "ES512") {
    hash = crypto.createHash("sha512");
  } else if (["EdDSA", "Ed25519"].includes(alg) && crv === "Ed25519") {
    hash = crypto.createHash("sha512");
  } else if (["EdDSA", "Ed448"].includes(alg) && crv === "Ed448") {
    hash = crypto.createHash("shake256", { outputLength: 114 });
  } else {
    throw new TypeError(`unsupported OIDC hash algorithm ${alg}/${crv || ""}`);
  }

  const digest = hash.update(value, "ascii").digest();
  return digest.subarray(0, digest.length / 2).toString("base64url");
}
module.exports.oidcHash = oidcHash;

// Build an ES256 DPoP proof with a fresh key (embedded public jwk in the
// header, per RFC 9449) for the inbound leg: a real JS client proof that
// Attesto.DPoP.verify_proof must accept. Returns {proof, jkt}.
async function buildDpopProof(htm, htu, iat, jti) {
  const j = await jose();
  const { publicKey, privateKey } = await j.generateKeyPair("ES256", {
    extractable: true,
  });
  const publicJwk = await j.exportJWK(publicKey);
  const jkt = await j.calculateJwkThumbprint(publicJwk, "sha256");
  const proof = await new j.SignJWT({ htm, htu, iat, jti })
    .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: publicJwk })
    .sign(privateKey);
  return { proof, jkt };
}
module.exports.buildDpopProof = buildDpopProof;

// Sign a JWT from a JWK (private) - the inbound leg passes Attesto's keystore
// key as a JWK map so jose signs a token Attesto's verifier must accept.
// `typ` overrides the header typ (used for the at+jwt confusion test).
async function signJwtJwk(claims, jwk, alg, typ) {
  const j = await jose();
  const key = await j.importJWK(jwk, alg);
  return await new j.SignJWT(claims)
    .setProtectedHeader({ alg, typ: typ || "JWT" })
    .sign(key);
}
module.exports.signJwtJwk = signJwtJwk;

// --- adversarial artifact producers (must be REJECTED by Attesto) ---

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// An unsecured (alg:none) JWT: header.payload. with an empty signature.
async function signAlgNone(claims, typ) {
  return (
    b64urlJson({ alg: "none", typ: typ || "JWT" }) +
    "." +
    b64urlJson(claims) +
    "."
  );
}
module.exports.signAlgNone = signAlgNone;

// HS256 signed with an arbitrary secret (base64). The classic RS256->HS256
// confusion attack passes the server's RSA public key bytes as the HMAC key.
async function signHs256(claims, secretBase64, typ) {
  const j = await jose();
  const secret = Buffer.from(secretBase64, "base64");
  return await new j.SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: typ || "JWT" })
    .sign(secret);
}
module.exports.signHs256 = signHs256;

// ── WHATWG URL parsing (RFC 8252 §7.3 redirect-URI parity) ─────────────────
//
// `new URL()` is Node's implementation of the WHATWG URL Standard - the same
// parser browsers use to resolve a `Location` header. That makes it the
// authority on where a redirect URI ACTUALLY sends a user agent, which is a
// different question from how Elixir's RFC 3986 `URI.parse/1` decomposes the
// same string. The two genuinely disagree on some inputs (a backslash in the
// authority, for one), so the loopback matcher's accept-set has to be checked
// against this parser, not against its own.
//
// Returns the resolved components, or `{ok: false}` for a string WHATWG
// refuses outright (an out-of-range port, an IPv6 zone id).
function whatwgUrl(input) {
  try {
    const u = new URL(input);
    return {
      ok: true,
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port,
      pathname: u.pathname,
      search: u.search,
      hash: u.hash,
    };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}
module.exports.whatwgUrl = whatwgUrl;

// ── Differential fuzzing oracle helpers ────────────────────────────────────

function formatErr(err) {
  return {
    ok: false,
    error: (err && err.constructor && err.constructor.name) || "Error",
    code: (err && err.code) || null,
    message: String((err && err.message) || err),
  };
}

// 1. JWS compact verification oracle via panva/jose
async function fuzzVerifyJws(token, publicJwk, algorithms) {
  try {
    const j = await jose();
    const alg = (algorithms && algorithms[0]) || publicJwk.alg || "ES256";
    const key = await j.importJWK(publicJwk, alg);
    const { payload, protectedHeader } = await j.compactVerify(token, key, {
      algorithms,
    });
    const text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
    const claims = JSON.parse(text);
    if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
      return {
        ok: false,
        error: "JWTInvalid",
        code: "ERR_JWT_INVALID",
        message: "JWT Claims Set must be a top-level JSON object",
      };
    }
    return { ok: true, header: protectedHeader, claims };
  } catch (err) {
    return formatErr(err);
  }
}
module.exports.fuzzVerifyJws = fuzzVerifyJws;

// 2. JWE compact decryption & encryption oracle via panva/jose
async function fuzzDecryptJwe(compact, privateJwk, algs, encs) {
  try {
    const j = await jose();
    const key = await j.importJWK(privateJwk, "ECDH-ES");
    const { plaintext, protectedHeader } = await j.compactDecrypt(compact, key, {
      keyManagementAlgorithms: algs,
      contentEncryptionAlgorithms: encs,
    });
    return {
      ok: true,
      plaintext_b64: Buffer.from(plaintext).toString("base64url"),
      header: protectedHeader,
    };
  } catch (err) {
    return formatErr(err);
  }
}
module.exports.fuzzDecryptJwe = fuzzDecryptJwe;

async function fuzzEncryptJwe(publicJwk, plaintextB64, protectedHeader) {
  const j = await jose();
  const key = await j.importJWK(publicJwk, "ECDH-ES");
  const plaintext = Buffer.from(plaintextB64, "base64url");
  return await new j.CompactEncrypt(plaintext)
    .setProtectedHeader(protectedHeader)
    .encrypt(key);
}
module.exports.fuzzEncryptJwe = fuzzEncryptJwe;

// 3. SD-JWT verification & disclosure decoding oracle via @sd-jwt/core
async function fuzzDecodeDisclosures(disclosures, sdAlg) {
  try {
    const { core } = await sdJwtLibraries();
    const alg = sdAlg || "sha-256";
    const out = {};
    for (const d of disclosures) {
      const decoded = core.Disclosure.fromEncodeSync(d, {
        hasher: sdHasher,
        alg,
      });
      const digest = await decoded.digest({ hasher: sdHasher, alg });
      const arr = decoded.key !== undefined
        ? [decoded.salt, decoded.key, decoded.value]
        : [decoded.salt, decoded.value];
      out[digest] = arr;
    }
    return { ok: true, disclosures: out };
  } catch (err) {
    return formatErr(err);
  }
}
module.exports.fuzzDecodeDisclosures = fuzzDecodeDisclosures;

async function fuzzVerifySdJwt(
  combined,
  issuerPublicJwk,
  algorithms,
  holderPublicJwk,
  kbOpts,
) {
  try {
    const j = await jose();
    const { core } = await sdJwtLibraries();
    const alg = (algorithms && algorithms[0]) || "ES256";
    const issuerKey = await j.importJWK(issuerPublicJwk, alg);

    const verifier = async (data, signature) => {
      try {
        await j.compactVerify(`${data}.${signature}`, issuerKey, {
          algorithms: algorithms || ["ES256"],
        });
        return true;
      } catch (_e) {
        return false;
      }
    };

    const kbRequired = Boolean(kbOpts && kbOpts.require_kb);
    const kbVerifier = holderPublicJwk
      ? async (data, signature) => {
          try {
            const kbAlg = (kbOpts && kbOpts.alg) || "ES256";
            const hKey = await j.importJWK(holderPublicJwk, kbAlg);
            await j.compactVerify(`${data}.${signature}`, hKey, {
              algorithms: [kbAlg],
            });
            return true;
          } catch (_e) {
            return false;
          }
        }
      : undefined;

    const instance = new core.SDJwtInstance({
      verifier,
      kbVerifier,
      hasher: sdHasher,
    });

    const verifyOptions = kbRequired
      ? {
          keyBindingNonce: (kbOpts && kbOpts.nonce) || "",
          currentDate: kbOpts && kbOpts.now,
          skewSeconds: 60,
        }
      : undefined;

    const verified = await instance.verify(combined, verifyOptions);

    if (kbRequired && kbOpts) {
      if (!verified.kb || !verified.kb.payload || !verified.kb.header) {
        throw new Error("Missing KB-JWT in verified SD-JWT");
      }
      if (verified.kb.header.typ !== "kb+jwt") {
        throw new Error(`Invalid KB-JWT typ: ${verified.kb.header.typ}`);
      }
      if (kbOpts.nonce && verified.kb.payload.nonce !== kbOpts.nonce) {
        throw new Error("KB-JWT nonce mismatch");
      }
      if (kbOpts.audience && verified.kb.payload.aud !== kbOpts.audience) {
        throw new Error("KB-JWT aud mismatch");
      }
      if (typeof verified.kb.payload.iat !== "number") {
        throw new Error("KB-JWT missing numeric iat");
      }
      if (kbOpts.now !== undefined) {
        const maxAge = kbOpts.max_age_seconds || 300;
        if (
          verified.kb.payload.iat > kbOpts.now + 60 ||
          verified.kb.payload.iat < kbOpts.now - maxAge
        ) {
          throw new Error("KB-JWT iat out of window");
        }
      }
    }

    return {
      ok: true,
      claims: verified.payload,
      header: verified.header,
      kb: verified.kb ? verified.kb.payload : null,
    };
  } catch (err) {
    return formatErr(err);
  }
}
module.exports.fuzzVerifySdJwt = fuzzVerifySdJwt;

// 4. mdoc DeviceResponse verification oracles via @auth0/mdl
function toPlainMdocValue(val) {
  if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
    return { __bytes_b64: Buffer.from(val).toString("base64url") };
  }
  if (val instanceof Date) {
    return Math.floor(val.getTime() / 1000);
  }
  if (val instanceof Map) {
    const obj = {};
    for (const [k, v] of val.entries()) {
      obj[String(k)] = toPlainMdocValue(v);
    }
    return obj;
  }
  if (Array.isArray(val)) {
    return val.map(toPlainMdocValue);
  }
  if (val && typeof val === "object") {
    const obj = {};
    for (const [k, v] of Object.entries(val)) {
      obj[k] = toPlainMdocValue(v);
    }
    return obj;
  }
  return val;
}

// 4a. Raw @auth0/mdl Verifier.verifyData + verifyDeviceSignature (exposes @auth0/mdl crash on cert-less IssuerAuth)
async function fuzzVerifyMdocRawVerifier(
  deviceResponseInput,
  isRawCborB64,
  sessionTranscriptB64,
) {
  try {
    const mdl = require("@auth0/mdl");
    const { cborDecode, cborEncode } = require("@auth0/mdl/lib/cbor");
    const { DataItem } = require("@auth0/mdl/lib/cbor/DataItem");
    const rawBytes = Buffer.from(deviceResponseInput, "base64url");
    const decodedSt = cborDecode(Buffer.from(sessionTranscriptB64, "base64url"));
    const sessionTranscriptBytes = cborEncode(DataItem.fromData(decodedSt));
    const parsed = mdl.parse(rawBytes);
    const verifier = new mdl.Verifier([]);
    const checks = [];
    const onCheck = (c) => checks.push(c);
    for (const doc of parsed.documents) {
      await verifier.verifyData(doc, onCheck);
      await verifier.verifyDeviceSignature(doc, {
        sessionTranscriptBytes,
        onCheck,
      });
    }
    const failed = checks.filter((c) => c.status !== "PASSED");
    if (failed.length > 0) {
      return {
        ok: false,
        error: "MdlVerificationFailed",
        code: failed[0].check,
        message: failed[0].reason || failed[0].check,
      };
    }
    return { ok: true, documentCount: parsed.documents.length };
  } catch (err) {
    return formatErr(err);
  }
}
module.exports.fuzzVerifyMdocRawVerifier = fuzzVerifyMdocRawVerifier;

// 4b. Step-by-step @auth0/mdl parse + IssuerAuth.verify + IssuerSignedItem.isValid + Verifier.verifyDeviceSignature
async function fuzzVerifyMdocDeviceResponse(
  deviceResponseInput,
  sessionTranscriptB64,
  issuerPublicJwk,
  opts,
) {
  try {
    const mdl = require("@auth0/mdl");
    const { cborDecode, cborEncode } = require("@auth0/mdl/lib/cbor");
    const { DataItem } = require("@auth0/mdl/lib/cbor/DataItem");
    const j = await jose();
    const rawBytes = Buffer.from(deviceResponseInput, "base64url");
    const decodedSt = cborDecode(Buffer.from(sessionTranscriptB64, "base64url"));
    const sessionTranscriptBytes = cborEncode(DataItem.fromData(decodedSt));
    const parsed = mdl.parse(rawBytes);

    if (parsed.status !== 0) {
      throw new Error(`DeviceResponse status is ${parsed.status}, expected 0`);
    }
    if (!Array.isArray(parsed.documents) || parsed.documents.length === 0) {
      throw new Error("DeviceResponse has no documents");
    }

    const verifier = new mdl.Verifier([]);
    const results = [];

    for (const doc of parsed.documents) {
      const issuerAuth = doc.issuerSigned && doc.issuerSigned.issuerAuth;
      if (!issuerAuth) throw new Error("Missing issuerAuth");

      const issuerKey = await j.importJWK(issuerPublicJwk, issuerAuth.algName);
      if (!(await issuerAuth.verify(issuerKey))) {
        throw new Error("IssuerAuth COSE_Sign1 signature invalid");
      }

      const mso = issuerAuth.decodedPayload;
      if (!mso || mso.version !== "1.0") {
        throw new Error("Invalid MSO version");
      }
      if (mso.digestAlgorithm !== "SHA-256") {
        throw new Error(`Unsupported digestAlgorithm: ${mso.digestAlgorithm}`);
      }
      if (doc.docType !== mso.docType) {
        throw new Error(`Document docType (${doc.docType}) != MSO docType (${mso.docType})`);
      }
      if (opts && opts.expected_doc_type && doc.docType !== opts.expected_doc_type) {
        throw new Error(`Unexpected docType: ${doc.docType}`);
      }

      const vi = mso.validityInfo;
      if (!vi || !(vi.signed instanceof Date) || !(vi.validFrom instanceof Date) || !(vi.validUntil instanceof Date)) {
        throw new Error("Invalid MSO validityInfo");
      }
      const signedSec = Math.floor(vi.signed.getTime() / 1000);
      const validFromSec = Math.floor(vi.validFrom.getTime() / 1000);
      const validUntilSec = Math.floor(vi.validUntil.getTime() / 1000);
      if (!(signedSec <= validFromSec && validFromSec < validUntilSec)) {
        throw new Error("Invalid validityInfo ordering");
      }
      const nowSec = opts && typeof opts.now === "number" ? opts.now : Math.floor(Date.now() / 1000);
      const skew = 60;
      if (nowSec - skew >= validUntilSec) {
        throw new Error("MSO expired");
      }
      if (nowSec + skew < validFromSec) {
        throw new Error("MSO not yet valid");
      }

      const namespaces = {};
      for (const ns of doc.issuerSignedNameSpaces) {
        const items = doc.issuerSigned.nameSpaces[ns] || [];
        const checks = await Promise.all(
          items.map((item) => item.isValid(ns, issuerAuth)),
        );
        if (checks.some((valid) => !valid)) {
          throw new Error(`Digest verification failed for namespace ${ns}`);
        }
        namespaces[ns] = toPlainMdocValue(doc.getIssuerNameSpace(ns));
      }

      const devChecks = [];
      await verifier.verifyDeviceSignature(doc, {
        sessionTranscriptBytes,
        onCheck: (c) => devChecks.push(c),
      });
      const devFailed = devChecks.filter((c) => c.status !== "PASSED");
      if (devFailed.length > 0) {
        throw new Error(`Device signature failed: ${devFailed[0].reason || devFailed[0].check}`);
      }

      results.push({
        doc_type: doc.docType,
        namespaces,
        validity: {
          signed: signedSec,
          valid_from: validFromSec,
          valid_until: validUntilSec,
        },
      });
    }

    return { ok: true, documents: results };
  } catch (err) {
    return formatErr(err);
  }
}
module.exports.fuzzVerifyMdocDeviceResponse = fuzzVerifyMdocDeviceResponse;

// 5. DPoP proof verification oracle via panva/jose EmbeddedJWK + WHATWG URL
async function fuzzVerifyDpop(proof, opts) {
  try {
    const j = await jose();
    const allowedAlgs = (opts && opts.algorithms) || [
      "ES256",
      "ES384",
      "ES512",
      "RS256",
      "RS384",
      "RS512",
      "PS256",
      "PS384",
      "PS512",
      "EdDSA",
    ];
    const { payload, protectedHeader } = await j.jwtVerify(
      proof,
      j.EmbeddedJWK,
      {
        typ: "dpop+jwt",
        algorithms: allowedAlgs,
        currentDate: new Date(0),
      },
    );

    if (typeof payload.htm !== "string" || payload.htm !== opts.http_method) {
      throw new Error(`htm mismatch: ${payload.htm}`);
    }
    if (typeof payload.htu !== "string" || typeof opts.http_uri !== "string") {
      throw new Error("htu missing or not string");
    }

    const u1 = new URL(payload.htu);
    const u2 = new URL(opts.http_uri);
    if (u1.username || u1.password) {
      throw new Error("htu contains userinfo");
    }
    if (
      u1.protocol !== u2.protocol ||
      u1.hostname !== u2.hostname ||
      u1.port !== u2.port ||
      u1.pathname !== u2.pathname
    ) {
      throw new Error(`htu mismatch: ${u1.origin}${u1.pathname} vs ${u2.origin}${u2.pathname}`);
    }

    if (typeof payload.iat !== "number" || !Number.isInteger(payload.iat) || payload.iat < 0) {
      throw new Error("invalid iat");
    }
    const now = typeof opts.now === "number" ? opts.now : Math.floor(Date.now() / 1000);
    const maxAge = typeof opts.max_age_seconds === "number" ? opts.max_age_seconds : 60;
    if (payload.iat > now + 60) {
      throw new Error("iat in the future");
    }
    if (payload.iat < now - maxAge) {
      throw new Error("proof expired");
    }

    if (typeof payload.jti !== "string" || payload.jti.length === 0) {
      throw new Error("invalid jti");
    }

    if (opts.access_token !== undefined && opts.access_token !== null) {
      if (typeof payload.ath !== "string") {
        throw new Error("missing ath");
      }
      const expectedAth = crypto
        .createHash("sha256")
        .update(opts.access_token, "ascii")
        .digest("base64url");
      if (payload.ath !== expectedAth) {
        throw new Error("ath mismatch");
      }
    }

    if (opts.expected_nonce !== undefined && opts.expected_nonce !== null) {
      if (payload.nonce !== opts.expected_nonce) {
        throw new Error("nonce mismatch");
      }
    }

    const jkt = await j.calculateJwkThumbprint(protectedHeader.jwk, "sha256");
    return {
      ok: true,
      jkt,
      jti: payload.jti,
      htm: payload.htm,
      htu: payload.htu,
      iat: payload.iat,
      ath: payload.ath || null,
    };
  } catch (err) {
    return formatErr(err);
  }
}
module.exports.fuzzVerifyDpop = fuzzVerifyDpop;

