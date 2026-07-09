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
  const { payload, protectedHeader } = await j.jwtVerify(token, key, { algorithms: [alg] });
  return { header: protectedHeader, payload };
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

// Build an ES256 DPoP proof with a fresh key (embedded public jwk in the
// header, per RFC 9449) for the inbound leg: a real JS client proof that
// Attesto.DPoP.verify_proof must accept. Returns {proof, jkt}.
async function buildDpopProof(htm, htu, iat, jti) {
  const j = await jose();
  const { publicKey, privateKey } = await j.generateKeyPair("ES256", { extractable: true });
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
