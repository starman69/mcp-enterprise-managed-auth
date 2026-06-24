// ─────────────────────────────────────────────────────────────────────────────
// mcp-server — MCP Authorization Server (+ Resource Server) (port 3001)
//
// Phase 3 (this file): the **Authorization Server** role. It redeems an ID-JAG for an
// audience-restricted MCP access token via RFC 7523 jwt-bearer.
//   • GET  /.well-known/oauth-authorization-server   AS metadata (advertises the id-jag profile)
//   • GET  /jwks.json                                this AS's public signing keys
//   • POST /oauth/token  (grant_type=jwt-bearer, assertion=ID-JAG)  → MCP access token
//
// The key trust relationship: this AS does NOT run a login or consent flow. It accepts an ID-JAG
// minted by the enterprise IdP, validates it against the IdP's JWKS, and trusts the IdP's policy
// decision. There is deliberately no `authorization_endpoint` — the absence of a consent redirect
// is the whole point of Enterprise-Managed Authorization.
//
// Phase 4 will add the **Resource Server** role (PRM + protected /v1/*) to this same service.
// ─────────────────────────────────────────────────────────────────────────────

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const config = require('../shared/config');
const { createKeystore, sign } = require('../shared/keys');
const oauth = require('../shared/oauth');

const PORT = process.env.PORT || 3001;
const AS_ISSUER = config.mcpServerUrl; // this Authorization Server's issuer identifier
const RESOURCE = config.resource;      // RFC 8707 Resource Identifier of the MCP server (this service)
const IDP_ISSUER = config.idpUrl;      // the enterprise IdP we trust to mint ID-JAGs

const SUPPORTED_SCOPES = ['contexts:read', 'contexts:write'];

// The IdP's public keys, fetched (and cached) over HTTP. This is how the AS verifies an ID-JAG's
// signature without sharing any secret with the IdP — the trust is one signed, audience-bound JWT.
const IDP_JWKS = createRemoteJWKSet(new URL(`${IDP_ISSUER}/jwks.json`));

// Protected Resource Metadata location (RFC 9728) — advertised in 401 challenges so a client can
// discover which Authorization Server to use.
const PRM_URL = `${RESOURCE}/.well-known/oauth-protected-resource`;

// The protected data this MCP server exposes (mock "contexts"). Reachable only with a valid,
// audience-restricted access token carrying the contexts:read scope.
const CONTEXTS = [
  { id: 'ctx-001', name: 'Q3 planning notes', tags: ['planning'], updated: '2026-05-02' },
  { id: 'ctx-002', name: 'Incident #4821 timeline', tags: ['ops', 'incident'], updated: '2026-06-11' },
  { id: 'ctx-003', name: 'Onboarding runbook', tags: ['docs'], updated: '2026-04-20' },
];

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const bearerToken = (req) => {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  return m ? m[1] : null;
};

// Emit an RFC 6750 `WWW-Authenticate` challenge (with the RFC 9728 `resource_metadata` pointer) and
// the matching JSON error body.
function challenge(res, status, error, description, extra = {}) {
  const parts = [`Bearer realm="${RESOURCE}"`];
  if (error) parts.push(`error="${error}"`);
  if (description) parts.push(`error_description="${description}"`);
  for (const [k, v] of Object.entries(extra)) parts.push(`${k}="${v}"`);
  parts.push(`resource_metadata="${PRM_URL}"`);
  res.set('WWW-Authenticate', parts.join(', '));
  return res.status(status).json({ error: error || 'invalid_request', error_description: description });
}

async function main() {
  const keystore = await createKeystore({ alg: 'RS256' });

  const app = express();
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Landing page — quick index of what this service exposes.
  app.get('/', (req, res) => {
    res.type('html').send(`<!doctype html><meta charset="utf-8">
<body style="font:15px/1.6 system-ui;max-width:640px;margin:3rem auto;padding:0 1rem">
<h1>mcp-server <small style="color:#888">— MCP AS + RS (:${PORT})</small></h1>
<p><b>Authorization Server</b> — ID-JAG → access token:</p>
<ul>
  <li><a href="/.well-known/oauth-authorization-server">/.well-known/oauth-authorization-server</a></li>
  <li><a href="/jwks.json">/jwks.json</a></li>
  <li><code>POST /oauth/token</code> (grant_type=jwt-bearer, assertion=ID-JAG → access token)</li>
</ul>
<p><b>Resource Server</b> — protected MCP API:</p>
<ul>
  <li><a href="/.well-known/oauth-protected-resource">/.well-known/oauth-protected-resource</a> (PRM)</li>
  <li><code>GET /v1/contexts</code> (Bearer token, scope contexts:read)</li>
  <li><code>GET /v1/contexts/:id</code></li>
  <li><code>POST /mcp</code> (JSON-RPC initialize; declares the EMA extension)</li>
</ul>
</body>`);
  });

  // ── Authorization Server metadata (RFC 8414). ───────────────────────────────────────────────────
  app.get('/.well-known/oauth-authorization-server', (req, res) => {
    res.json({
      issuer: AS_ISSUER,
      token_endpoint: `${AS_ISSUER}/oauth/token`,
      jwks_uri: `${AS_ISSUER}/jwks.json`,
      grant_types_supported: [oauth.GRANT_JWT_BEARER],
      token_endpoint_auth_methods_supported: ['none'], // the signed ID-JAG is the authorization grant
      scopes_supported: SUPPORTED_SCOPES,
      response_types_supported: [], // intentionally empty — this AS has no authorization endpoint
      // ── EMA / ID-JAG surface: advertise that this AS accepts the id-jag authorization-grant profile.
      authorization_grant_profiles_supported: [oauth.GRANT_PROFILE_ID_JAG],
    });
  });

  // ── This AS's public signing keys (the RS in Phase 4, or any verifier, checks access tokens here).
  app.get('/jwks.json', (req, res) => res.json(keystore.jwks));

  // ── Token endpoint: RFC 7523 jwt-bearer. assertion = ID-JAG → audience-restricted access token. ──
  app.post('/oauth/token', asyncHandler(async (req, res) => {
    const { grant_type, assertion } = req.body;

    if (grant_type !== oauth.GRANT_JWT_BEARER)
      return res.status(400).json({ error: 'unsupported_grant_type', error_description: `expected ${oauth.GRANT_JWT_BEARER}` });
    if (!assertion)
      return res.status(400).json({ error: 'invalid_request', error_description: 'assertion (the ID-JAG) is required' });

    // Validate the ID-JAG: signature against the IdP JWKS, the custom typ header, iss, aud, and exp
    // are all enforced by jwtVerify; the resource claim we check ourselves (it is not a JWT-standard claim).
    let jag;
    try {
      ({ payload: jag } = await jwtVerify(assertion, IDP_JWKS, {
        typ: oauth.ID_JAG_TYP,   // must be oauth-id-jag+jwt
        issuer: IDP_ISSUER,      // must come from the IdP we trust
        audience: AS_ISSUER,     // must be addressed to THIS Authorization Server
      }));
    } catch (e) {
      return res.status(400).json({ error: 'invalid_grant', error_description: `ID-JAG validation failed: ${e.code || e.message}` });
    }

    // The ID-JAG's `resource` (if present) MUST be this MCP server (it scopes where the grant is valid).
    if (jag.resource && jag.resource !== RESOURCE)
      return res.status(400).json({ error: 'invalid_target', error_description: `ID-JAG resource "${jag.resource}" is not this MCP server (${RESOURCE})` });

    // Only grant scopes this server actually supports (defense in depth; the IdP already scoped them).
    const granted = (jag.scope || '').split(/\s+/).filter((s) => SUPPORTED_SCOPES.includes(s));
    if (granted.length === 0)
      return res.status(400).json({ error: 'invalid_scope', error_description: `ID-JAG carried no scope this server supports (supported: ${SUPPORTED_SCOPES.join(' ')})` });

    // Mint the MCP access token — a short-lived JWT (RFC 9068 typ "at+jwt") audience-restricted to
    // the MCP server identified by the ID-JAG's resource claim (RFC 8707).
    const accessToken = await sign(
      keystore,
      {
        iss: AS_ISSUER,
        sub: jag.sub,
        aud: jag.resource || RESOURCE, // audience restriction → the MCP server (enforced by the RS)
        client_id: jag.client_id,
        scope: granted.join(' '),
        jti: crypto.randomUUID(),
      },
      { typ: 'at+jwt', expiresIn: '15m' },
    );
    console.log(`[mcp-server] issued access token: sub=${jag.sub} aud=${jag.resource || RESOURCE} scope="${granted.join(' ')}"`);

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      scope: granted.join(' '),
    });
  }));

  // ── Resource Server role ──────────────────────────────────────────────────────────────────────

  // Protected Resource Metadata (RFC 9728): tells a client which AS issues tokens for this resource.
  app.get('/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
      resource: RESOURCE,
      authorization_servers: [AS_ISSUER],
      jwks_uri: `${AS_ISSUER}/jwks.json`,
      scopes_supported: SUPPORTED_SCOPES,
      bearer_methods_supported: ['header'],
      resource_name: 'MCP demo server',
    });
  });

  // Bearer-token guard. Verifies the access token and enforces the audience restriction that the AS
  // applied in Phase 3 — this is where "the token is only good for THIS MCP server" is enforced.
  // (AS and RS share a process here, so we verify against the local keystore; in a split deployment
  // the RS would verify against the AS's JWKS at /jwks.json.)
  const requireScope = (requiredScope) =>
    asyncHandler(async (req, res, next) => {
      const token = bearerToken(req);
      if (!token) return challenge(res, 401, 'invalid_request', 'missing bearer token');

      let claims;
      try {
        ({ payload: claims } = await jwtVerify(token, keystore.publicKey, {
          typ: 'at+jwt',
          issuer: AS_ISSUER,    // minted by our AS
          audience: RESOURCE,   // audience-restricted to THIS MCP server
        }));
      } catch (e) {
        return challenge(res, 401, 'invalid_token', e.code || e.message);
      }

      const scopes = (claims.scope || '').split(/\s+/).filter(Boolean);
      if (requiredScope && !scopes.includes(requiredScope))
        return challenge(res, 403, 'insufficient_scope', `requires scope '${requiredScope}'`, { scope: requiredScope });

      req.auth = claims;
      next();
    });

  // Protected MCP API. Requires a valid token with contexts:read.
  app.get('/v1/contexts', requireScope('contexts:read'), (req, res) => {
    res.json({ sub: req.auth.sub, count: CONTEXTS.length, contexts: CONTEXTS });
  });

  app.get('/v1/contexts/:id', requireScope('contexts:read'), (req, res) => {
    const ctx = CONTEXTS.find((c) => c.id === req.params.id);
    if (!ctx) return res.status(404).json({ error: 'not_found', error_description: `no context ${req.params.id}` });
    res.json({ sub: req.auth.sub, context: ctx });
  });

  // Minimal MCP endpoint (JSON-RPC). The `initialize` handshake is where both sides declare support
  // for the Enterprise-Managed Authorization extension. It is a protected call — by the time a client
  // initializes, it already holds an access token obtained via the ID-JAG chain. (requireScope() with
  // no argument just requires a valid, audience-restricted token.)
  app.post('/mcp', requireScope(), (req, res) => {
    const { id = null, jsonrpc, method, params } = req.body || {};
    if (jsonrpc !== '2.0')
      return res.status(400).json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'invalid request (jsonrpc must be "2.0")' } });

    if (method === 'initialize') {
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: (params && params.protocolVersion) || '2025-06-18',
          capabilities: { extensions: { [oauth.EMA_EXTENSION_ID]: {} } },
          serverInfo: { name: 'mcp-ema-demo-server', version: '0.1.0' },
        },
      });
    }
    return res.status(404).json({ jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${method}` } });
  });

  app.use((err, req, res, next) => {
    console.error('[mcp-server] error:', err);
    res.status(500).json({ error: 'server_error', error_description: err.message });
  });

  app.listen(PORT, () => {
    console.log(`mcp-server running at ${AS_ISSUER} (port ${PORT}); IdP: ${IDP_ISSUER}`);
    console.log(`  kid=${keystore.kid} alg=${keystore.alg}`);
  });
}

main().catch((err) => {
  console.error('[mcp-server] failed to start:', err);
  process.exit(1);
});
