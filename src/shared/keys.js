// Shared dev-key / JWKS helper for the EMA POC.
//
// Every signing service (the mock IdP now; the MCP Authorization Server later) generates its OWN
// ephemeral keypair at startup and publishes the public half at a `/jwks.json` endpoint. Nothing
// is persisted and no private key ever touches disk — `git clone && npm run dev` always comes up
// with fresh keys. These are DEV keys only: a production deployment would hold the signing key in a
// managed key store / HSM (e.g. a cloud KMS), and a real enterprise IdP would sign with its own keys.
//
// We use `jose` (not `jsonwebtoken`) throughout because the ID-JAG needs a custom JWT `typ` header
// (`oauth-id-jag+jwt`) and a real JWKS with a stable `kid` — both awkward with jsonwebtoken.

const { generateKeyPair, exportJWK, calculateJwkThumbprint, SignJWT } = require('jose');

/**
 * Generate a signing keystore: a fresh keypair plus the public JWK / JWKS to publish.
 *
 * @param {object}  [opts]
 * @param {string}  [opts.alg='RS256']  JWS algorithm (RS256 keeps the JWKS human-readable).
 * @returns {Promise<{alg, kid, privateKey, publicKey, publicJwk, jwks}>}
 */
async function createKeystore({ alg = 'RS256' } = {}) {
  // `extractable: true` is required so we can export the public half as a JWK.
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });

  const publicJwk = await exportJWK(publicKey);
  // RFC 7638 thumbprint as the key id — stable for a given key, and what a verifier matches on.
  const kid = await calculateJwkThumbprint(publicJwk);
  Object.assign(publicJwk, { kid, alg, use: 'sig' });

  return {
    alg,
    kid,
    privateKey,
    publicKey,
    publicJwk,
    jwks: { keys: [publicJwk] }, // serve this verbatim at /jwks.json
  };
}

/**
 * Sign a set of claims into a compact JWS, stamping `alg`/`kid`/`typ` into the protected header
 * and `iat`/`exp` into the payload. Callers own the rest of the claims (iss, sub, aud, …) so the
 * exact wire shape stays visible at each call site.
 *
 * @param {object} keystore           From {@link createKeystore}.
 * @param {object} claims             JWT payload (iss, sub, aud, nonce, email, …).
 * @param {object} [opts]
 * @param {string} [opts.typ='JWT']   Protected-header `typ` (e.g. `oauth-id-jag+jwt` in Phase 2).
 * @param {string|number} [opts.expiresIn='10m']  `exp` as a jose time string or seconds-from-now.
 * @returns {Promise<string>}         Compact JWT.
 */
async function sign(keystore, claims, { typ = 'JWT', expiresIn = '10m' } = {}) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: keystore.alg, kid: keystore.kid, typ })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(keystore.privateKey);
}

module.exports = { createKeystore, sign };
