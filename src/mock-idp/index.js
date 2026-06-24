// ─────────────────────────────────────────────────────────────────────────────
// mock-idp — the enterprise IdP (port 3010)
//
// Phase 1 (this file): standard OIDC login so the MCP client can obtain an **ID Token**.
//   • GET  /.well-known/openid-configuration   OIDC discovery (+ the EMA id-jag profile callout)
//   • GET  /jwks.json                          public signing keys
//   • GET  /authorize                          login form (the corporate SSO page)
//   • POST /login                              validate creds → issue an auth code → redirect back
//   • POST /token  (grant_type=authorization_code)  → signed OIDC ID Token
//
// Phase 2 will add a second branch to /token: grant_type=…:token-exchange (RFC 8693) that takes the
// ID Token as subject_token, runs the policy engine, and mints an ID-JAG. The auth-code login here
// is deliberately ordinary — the novelty of this demo lives in that later exchange, not the login.
// ─────────────────────────────────────────────────────────────────────────────

const crypto = require('crypto');
const express = require('express');
const { jwtVerify } = require('jose');
const config = require('../shared/config');
const { createKeystore, sign } = require('../shared/keys');
const oauth = require('../shared/oauth');
const policy = require('./policy');
const users = require('./users');

const PORT = process.env.PORT || 3010;
const ISSUER = config.idpUrl;

// Targets the ID-JAG is bound to (see the MCP EMA spec):
//   • aud      = the issuer identifier of the Resource Authorization Server (the MCP AS)
//   • resource = the Resource Identifier (RFC 8707) of the MCP server
// In this POC the MCP server is both AS and RS, so these two values coincide.
const MCP_AS_ISSUER = config.mcpServerUrl;
const MCP_RESOURCE = config.resource;

// Demo client registry. A real IdP registers apps (or supports Dynamic Client Registration, RFC 7591);
// here we hardcode the one MCP client, its redirect_uri, and a secret. The browser login leg is a
// public client (auth method "none"); the token-exchange leg authenticates with the secret.
const CLIENTS = {
  'mcp-client-demo': {
    secret: 'mcp-client-demo-secret',
    redirectUris: [`${config.clientUrl}/callback`],
  },
};

// Short-lived, single-use authorization codes: code -> { sub, clientId, redirectUri, nonce, scope, exp }
const authCodes = new Map();
const AUTH_CODE_TTL = 60; // seconds

const nowSec = () => Math.floor(Date.now() / 1000);
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// PKCE (RFC 7636): the verifier hashes to the challenge under S256.
const base64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const pkceChallenge = (verifier) => base64url(crypto.createHash('sha256').update(verifier).digest());

// ── HTML helpers (the login page; kept tiny and dependency-free) ─────────────────────────────────
const esc = (s = '') =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function renderLogin(params, error) {
  const hidden = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(params[k] || '')}">`)
    .join('\n      ');
  const demo = users.map((u) => `<code>${esc(u.username)}</code> / <code>${esc(u.password)}</code>`).join(' &nbsp;·&nbsp; ');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in — Acme Corp IdP</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{font:15px/1.5 system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;min-height:100vh;margin:0}
  .card{background:#1e293b;padding:2rem 2.25rem;border-radius:12px;width:340px;box-shadow:0 10px 40px rgba(0,0,0,.4)}
  h1{font-size:1.1rem;margin:0 0 .25rem} .sub{color:#94a3b8;font-size:.85rem;margin:0 0 1.25rem}
  label{display:block;font-size:.8rem;color:#94a3b8;margin:.75rem 0 .25rem}
  input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:.55rem .65rem;border-radius:7px;border:1px solid #334155;background:#0f172a;color:#e2e8f0}
  button{margin-top:1.25rem;width:100%;padding:.6rem;border:0;border-radius:7px;background:#6366f1;color:#fff;font-weight:600;cursor:pointer}
  button:hover{background:#4f46e5}
  .err{background:#7f1d1d;color:#fecaca;padding:.5rem .65rem;border-radius:7px;font-size:.85rem;margin-bottom:1rem}
  .demo{margin-top:1rem;font-size:.75rem;color:#64748b}
</style></head>
<body><form class="card" method="post" action="/login">
  <h1>Acme Corp</h1><p class="sub">Sign in to continue to <b>${esc(params.client_id || 'the MCP client')}</b></p>
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <label for="username">Username</label>
  <input id="username" name="username" type="text" autocomplete="username" autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  ${hidden}
  <button type="submit">Sign in</button>
  <p class="demo">Demo users: ${demo}</p>
</form></body></html>`;
}

async function main() {
  const keystore = await createKeystore({ alg: 'RS256' });

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Landing page — quick index of what this service exposes.
  app.get('/', (req, res) => {
    res.type('html').send(`<!doctype html><meta charset="utf-8">
<body style="font:15px/1.6 system-ui;max-width:640px;margin:3rem auto;padding:0 1rem">
<h1>mock-idp <small style="color:#888">— enterprise IdP (:${PORT})</small></h1>
<p>Enterprise IdP: OIDC login (PKCE) → ID Token, then RFC 8693 token-exchange → ID-JAG. Endpoints:</p>
<ul>
  <li><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a></li>
  <li><a href="/jwks.json">/jwks.json</a></li>
  <li><code>GET /authorize</code> (login; requires PKCE — start it from the <a href="${config.clientUrl}">MCP client</a>)</li>
  <li><code>POST /token</code> (grant_type=authorization_code → ID Token · grant_type=token-exchange → ID-JAG)</li>
</ul></body>`);
  });

  // ── OIDC discovery (RFC 8414 / OpenID Connect Discovery) ───────────────────────────────────────
  app.get('/.well-known/openid-configuration', (req, res) => {
    res.json({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: [
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:token-exchange', // Phase 2: ID Token → ID-JAG
      ],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [keystore.alg],
      scopes_supported: ['openid', 'profile', 'email', 'groups'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email', 'groups'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      // PKCE (OAuth 2.1) and RFC 9207 authorization-response issuer identification.
      code_challenge_methods_supported: ['S256'],
      authorization_response_iss_parameter_supported: true,
      // ── EMA / ID-JAG surface: the one field that marks this IdP as supporting the extension. ──
      authorization_grant_profiles_supported: ['urn:ietf:params:oauth:grant-profile:id-jag'],
    });
  });

  // ── Public signing keys ────────────────────────────────────────────────────────────────────────
  app.get('/jwks.json', (req, res) => res.json(keystore.jwks));

  // ── Authorization endpoint: render the login form, carrying the OAuth request params forward. ───
  app.get('/authorize', (req, res) => {
    const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method } = req.query;
    const client = CLIENTS[client_id];
    if (response_type !== 'code') return res.status(400).send('unsupported_response_type (expected "code")');
    if (!client) return res.status(400).send('unknown client_id');
    if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send('invalid redirect_uri');
    // PKCE is mandatory (OAuth 2.1). Only S256 is accepted.
    if (!code_challenge) return res.status(400).send('invalid_request: code_challenge is required (PKCE)');
    if (code_challenge_method !== 'S256') return res.status(400).send('invalid_request: code_challenge_method must be S256');
    res.type('html').send(renderLogin(req.query));
  });

  // ── Login: validate credentials → mint a one-time auth code → redirect back to the client. ──────
  app.post('/login', (req, res) => {
    const { username, password, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method } = req.body;
    const client = CLIENTS[client_id];
    if (!client || !client.redirectUris.includes(redirect_uri)) return res.status(400).send('invalid client/redirect_uri');
    // PKCE is mandatory (OAuth 2.1) — carried through the login form from /authorize.
    if (!code_challenge || code_challenge_method !== 'S256')
      return res.status(400).send('invalid_request: PKCE S256 code_challenge is required');

    const user = users.find((u) => u.username === username && u.password === password);
    if (!user) return res.status(401).type('html').send(renderLogin(req.body, 'Invalid username or password.'));

    const code = crypto.randomUUID();
    authCodes.set(code, {
      sub: user.sub,
      clientId: client_id,
      redirectUri: redirect_uri,
      nonce: nonce || null,
      scope: scope || 'openid',
      codeChallenge: code_challenge, // verified at the token endpoint (PKCE)
      authTime: nowSec(),
      exp: nowSec() + AUTH_CODE_TTL,
    });

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    url.searchParams.set('iss', ISSUER); // RFC 9207 authorization-response issuer identification
    res.redirect(url.toString());
  });

  // ── Token endpoint. Two grants share it:
  //     • authorization_code (Phase 1)  → OIDC ID Token
  //     • token-exchange    (Phase 2)  → ID-JAG, after the policy gate
  app.post('/token', asyncHandler(async (req, res) => {
    const { grant_type } = req.body;

    if (grant_type === oauth.GRANT_AUTHORIZATION_CODE) return issueIdToken(req, res, keystore);
    if (grant_type === oauth.GRANT_TOKEN_EXCHANGE) return issueIdJag(req, res, keystore);

    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: `grant_type "${grant_type}" not supported`,
    });
  }));

  app.use((err, req, res, next) => {
    console.error('[mock-idp] error:', err);
    res.status(500).json({ error: 'server_error', error_description: err.message });
  });

  app.listen(PORT, () => {
    console.log(`mock-idp running at ${ISSUER} (port ${PORT})`);
    console.log(`  kid=${keystore.kid} alg=${keystore.alg}`);
  });
}

// authorization_code → OIDC ID Token. Pulled out so Phase 2's token-exchange branch sits beside it.
async function issueIdToken(req, res, keystore) {
  const { code, client_id, redirect_uri, code_verifier } = req.body;
  const rec = authCodes.get(code);
  if (!rec) return res.status(400).json({ error: 'invalid_grant', error_description: 'unknown or used code' });
  authCodes.delete(code); // single use
  if (rec.exp < nowSec()) return res.status(400).json({ error: 'invalid_grant', error_description: 'code expired' });
  if (rec.clientId !== client_id || rec.redirectUri !== redirect_uri)
    return res.status(400).json({ error: 'invalid_grant', error_description: 'client_id / redirect_uri mismatch' });
  // PKCE verification (RFC 7636): the presented verifier must hash to the stored challenge.
  if (!code_verifier) return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier is required (PKCE)' });
  if (pkceChallenge(code_verifier) !== rec.codeChallenge)
    return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });

  const user = users.find((u) => u.sub === rec.sub);
  if (!user) return res.status(400).json({ error: 'invalid_grant', error_description: 'user no longer exists' });

  const idToken = await sign(
    keystore,
    {
      iss: ISSUER,
      sub: user.sub,
      aud: client_id,
      nonce: rec.nonce || undefined,
      auth_time: rec.authTime,
      name: user.name,
      email: user.email,
      groups: user.groups, // carried into the ID-JAG decision in Phase 2
    },
    { typ: 'JWT', expiresIn: '1h' },
  );

  // OIDC token response. We also mint an opaque access token for shape-completeness, but the EMA
  // flow only uses the **id_token** (it becomes the subject_token of the Phase-2 exchange).
  res.json({
    access_token: crypto.randomUUID(),
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
    scope: rec.scope,
  });
}

// ── RFC 8693 token exchange → ID-JAG (Phase 2). ──────────────────────────────────────────────────
// subject_token (the ID Token) ──policy gate──▶ ID-JAG bound to the MCP AS (aud) + MCP server (resource).
async function issueIdJag(req, res, keystore) {
  const {
    requested_token_type, subject_token, subject_token_type,
    audience, resource, scope, client_id, client_secret,
  } = req.body;

  // 1. Authenticate the (confidential) client.
  const client = CLIENTS[client_id];
  if (!client || client.secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client', error_description: 'unknown client_id or bad client_secret' });
  }

  // 2. Validate the exchange request shape (exact URNs — see ../shared/oauth.js).
  if (requested_token_type !== oauth.TOKEN_TYPE_ID_JAG)
    return res.status(400).json({ error: 'invalid_request', error_description: `requested_token_type must be ${oauth.TOKEN_TYPE_ID_JAG}` });
  if (subject_token_type !== oauth.TOKEN_TYPE_ID_TOKEN)
    return res.status(400).json({ error: 'invalid_request', error_description: `subject_token_type must be ${oauth.TOKEN_TYPE_ID_TOKEN}` });
  if (!subject_token)
    return res.status(400).json({ error: 'invalid_request', error_description: 'subject_token is required' });
  // audience MUST be the Resource AS issuer; resource (if present) MUST be the MCP server id.
  if (audience && audience !== MCP_AS_ISSUER)
    return res.status(400).json({ error: 'invalid_target', error_description: `audience must be the Resource AS issuer (${MCP_AS_ISSUER})` });
  if (resource && resource !== MCP_RESOURCE)
    return res.status(400).json({ error: 'invalid_target', error_description: `resource must be the MCP server id (${MCP_RESOURCE})` });

  // 3. Verify the subject ID Token. We issued it, so we verify against our own published keys.
  let claims;
  try {
    ({ payload: claims } = await jwtVerify(subject_token, keystore.publicKey, {
      issuer: ISSUER,
      audience: client_id, // the ID Token's audience is the client that logged the user in
    }));
  } catch (e) {
    return res.status(400).json({ error: 'invalid_grant', error_description: `subject_token (ID Token) invalid: ${e.message}` });
  }

  // 4. POLICY GATE — the EMA decision point. Deny here ⇒ no ID-JAG, centrally enforced.
  const decision = policy.evaluate({
    sub: claims.sub,
    groups: claims.groups || [],
    resource: resource || MCP_RESOURCE,
    scope: scope || '',
  });
  console.log(`[mock-idp] policy: sub=${claims.sub} resource=${resource || MCP_RESOURCE} -> ${decision.allow ? 'ALLOW' : 'DENY'} (${decision.reason})`);
  if (!decision.allow) {
    return res.status(403).json({ error: 'access_denied', error_description: decision.reason });
  }

  // 5. Mint the ID-JAG (typ: oauth-id-jag+jwt). Claim set per the MCP EMA spec / ID-JAG draft-04.
  const idJag = await sign(
    keystore,
    {
      jti: crypto.randomUUID(),
      iss: ISSUER,
      sub: claims.sub,
      email: claims.email,
      aud: MCP_AS_ISSUER,                 // Resource Authorization Server (the MCP AS)
      resource: resource || MCP_RESOURCE, // RFC 8707 id of the MCP server
      client_id,
      scope: decision.scope,              // granted scope (requested ∩ allowed)
    },
    { typ: oauth.ID_JAG_TYP, expiresIn: '5m' },
  );

  // 6. RFC 8693 response. token_type is the literal "N_A" — an ID-JAG is NOT an access token.
  return res.json({
    issued_token_type: oauth.TOKEN_TYPE_ID_JAG,
    access_token: idJag,
    token_type: oauth.TOKEN_TYPE_NA,
    scope: decision.scope,
    expires_in: 300,
  });
}

main().catch((err) => {
  console.error('[mock-idp] failed to start:', err);
  process.exit(1);
});
