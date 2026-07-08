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
