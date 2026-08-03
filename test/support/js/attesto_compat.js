// JS JOSE reference for attesto cross-language parity tests (test-support only).
// jose v5 is ESM-only, so it's loaded via dynamic import inside each async fn;
// the `nodejs` Elixir bridge loads this CommonJS module and calls these exports.
async function jose() {
  return await import("jose");
}

async function sdJwtLibraries() {
  const [vc, core] = await Promise.all([
    import("@sd-jwt/sd-jwt-vc"),
    import("@sd-jwt/core"),
  ]);
  return { vc, core };
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
