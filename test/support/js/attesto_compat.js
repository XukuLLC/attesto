// JS JOSE reference for attesto cross-language parity tests (test-support only).
// jose v5 is ESM-only, so it's loaded via dynamic import inside each async fn;
// the `nodejs` Elixir bridge loads this CommonJS module and calls these exports.
async function jose() {
  return await import("jose");
}

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

module.exports = { verifyJwt, jwkThumbprint, signJwt };
module.exports.verifyEdwardsJwt = verifyEdwardsJwt;

// Availability probe: resolves to "pong" iff jose loaded.
async function ping() {
  const j = await jose();
  return typeof j.jwtVerify === "function" ? "pong" : "no-jose";
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
