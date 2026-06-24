// ─────────────────────────────────────────────────────────────────────────────
// The EMA chain, as a set of orchestration helpers shared by the browser flow (index.js GET
// /callback) and the headless demo (index.js `demo` mode).
//
// The steps the client drives:
//   0. Discovery: hit the MCP server unauthenticated → 401 → Protected Resource Metadata (RFC 9728)
//        → Authorization Server metadata (RFC 8414). This is how the client learns the MCP server's
//        resource id, its Authorization Server, and that the AS advertises the ID-JAG grant profile —
//        instead of hardcoding any of it. (discover)
//   1. SSO login at the enterprise IdP → ID Token. The auth-code login uses PKCE (OAuth 2.1) and the
//        client validates the RFC 9207 `iss` of the authorization response. (beginLogin / completeLogin
//        / headlessLogin). The IdP base URL is org configuration — spec-correct for EMA.
//   2. token exchange at the IdP       → ID-JAG (policy gate) (tokenExchange)
//   3. jwt-bearer at the MCP AS        → access token         (jwtBearer)
//   4. use the token at the MCP server → initialize + data    (mcpInitialize / callApi)
//
// runChain() runs discovery (step 0) and then sequences steps 2–4 from an ID Token, using the
// discovered AS issuer / token endpoint / resource — recording a narratable step list and stopping
// at the policy gate if the IdP denies.
// ─────────────────────────────────────────────────────────────────────────────

const crypto = require('crypto');
const config = require('../shared/config');
const oauth = require('../shared/oauth');

const CLIENT_ID = process.env.CLIENT_ID || 'mcp-client-demo';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'mcp-client-demo-secret';
const REDIRECT_URI = `${config.clientUrl}/callback`;
const LOGIN_SCOPE = 'openid profile email groups';
const API_SCOPE = 'contexts:read';

const MCP_PROTOCOL_VERSION = '2025-06-18';

const form = (o) => new URLSearchParams(o).toString();
const postForm = (url, body) =>
  fetch(url, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form(body) });
const getJson = async (url) => {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`GET ${url} → HTTP ${res.status}`);
  return res.json();
};

// Decode a JWT for DISPLAY ONLY (no signature check) — lets the demo show what each token contains.
function decodeJwt(jwt) {
  try {
    const [h, p] = jwt.split('.');
    const dec = (s) => JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
    return { header: dec(h), payload: dec(p) };
  } catch {
    return null;
  }
}

// ── PKCE (RFC 7636 / OAuth 2.1) ────────────────────────────────────────────────────────────────
const base64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function pkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

// ── RFC 9207 authorization-response issuer validation ────────────────────────────────────────────
// Simple string comparison (RFC 3986 §6.2.1) — no normalization, per the MCP authorization spec.
function validateIss(returnedIss, expectedIss, issParamSupported) {
  if (issParamSupported) {
    if (!returnedIss) throw new Error('RFC 9207: AS advertises iss support but the response carried no iss — rejecting');
    if (returnedIss !== expectedIss) throw new Error(`RFC 9207: iss mismatch (got "${returnedIss}", expected "${expectedIss}")`);
  } else if (returnedIss && returnedIss !== expectedIss) {
    throw new Error(`RFC 9207: iss mismatch (got "${returnedIss}", expected "${expectedIss}")`);
  }
}

// ── Discovery (memoized) ─────────────────────────────────────────────────────────────────────────

// Enterprise IdP metadata (OpenID Connect Discovery). The IdP base URL is org configuration; we
// still discover its endpoints + iss + PKCE/iss support rather than hardcoding them.
let _idpMeta;
async function idpDiscover() {
  if (!_idpMeta) _idpMeta = await getJson(`${config.idpUrl}/.well-known/openid-configuration`);
  return _idpMeta;
}

// MCP-core discovery: unauthenticated probe → 401 WWW-Authenticate → PRM (RFC 9728) → AS metadata
// (RFC 8414). Returns everything the chain needs, learned from the wire.
let _mcpDisc;
async function discover() {
  if (_mcpDisc) return _mcpDisc;
  // 1. Probe the protected resource with no token; expect a 401 + WWW-Authenticate challenge.
  const probe = await fetch(`${config.mcpServerUrl}/v1/contexts`, { headers: { accept: 'application/json' } });
  const wwwAuth = probe.headers.get('www-authenticate') || '';
  // 2. Extract the PRM pointer from the challenge (RFC 6750 / RFC 9728). Fall back to the well-known.
  const rm = /resource_metadata="?([^",\s]+)"?/.exec(wwwAuth);
  const prmUrl = rm ? rm[1] : `${config.mcpServerUrl}/.well-known/oauth-protected-resource`;
  const prm = await getJson(prmUrl);
  // 3. Resolve the Authorization Server from the PRM and fetch its metadata.
  const asUrl = (prm.authorization_servers || [])[0];
  if (!asUrl) throw new Error('PRM did not list an authorization_servers entry');
  const asMeta = await getJson(`${asUrl}/.well-known/oauth-authorization-server`);
  const profiles = asMeta.authorization_grant_profiles_supported || [];
  _mcpDisc = {
    probeStatus: probe.status,
    wwwAuth,
    prmUrl,
    prm,
    asMeta,
    resource: prm.resource,                 // RFC 8707 id the token will be bound to
    asIssuer: asMeta.issuer,                // ID-JAG audience = the MCP AS issuer
    asTokenEndpoint: asMeta.token_endpoint, // where we redeem the ID-JAG (jwt-bearer)
    emaSupported: profiles.includes(oauth.GRANT_PROFILE_ID_JAG),
  };
  return _mcpDisc;
}

// ── Step 1: SSO login at the enterprise IdP (PKCE + RFC 9207 iss) ────────────────────────────────

// Browser: build the authorization URL and the per-request secrets the callback will need.
async function beginLogin() {
  const idp = await idpDiscover();
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const { verifier, challenge } = pkce();
  const q = new URLSearchParams({
    response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: LOGIN_SCOPE,
    state, nonce, code_challenge: challenge, code_challenge_method: 'S256',
  });
  return {
    url: `${idp.authorization_endpoint}?${q}`,
    state,
    session: { nonce, verifier, expectedIss: idp.issuer, issParamSupported: !!idp.authorization_response_iss_parameter_supported },
  };
}

// Browser callback: validate the RFC 9207 iss, then redeem the code (with the PKCE verifier).
async function completeLogin({ code, returnedIss, session }) {
  validateIss(returnedIss, session.expectedIss, session.issParamSupported);
  return exchangeCode(code, session.verifier);
}

// Redeem an authorization code for an ID Token, sending the PKCE code_verifier.
async function exchangeCode(code, codeVerifier) {
  const idp = await idpDiscover();
  const res = await postForm(idp.token_endpoint, {
    grant_type: oauth.GRANT_AUTHORIZATION_CODE, code, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`code exchange failed: ${JSON.stringify(body)}`);
  return body.id_token;
}

// Headless: post credentials, follow the redirect, validate state + iss, redeem the code with PKCE.
async function headlessLogin(username, password) {
  const idp = await idpDiscover();
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const { verifier, challenge } = pkce();
  const res = await postForm(`${config.idpUrl}/login`, {
    username, password, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: LOGIN_SCOPE,
    state, nonce, code_challenge: challenge, code_challenge_method: 'S256',
  });
  const loc = res.headers.get('location');
  if (!loc) throw new Error(`login did not redirect (HTTP ${res.status}) — bad credentials?`);
  const got = new URL(loc).searchParams;
  if (got.get('state') !== state) throw new Error('state mismatch on authorization response');
  validateIss(got.get('iss'), idp.issuer, !!idp.authorization_response_iss_parameter_supported);
  return exchangeCode(got.get('code'), verifier);
}

// ── Step 2: RFC 8693 token exchange at the IdP → ID-JAG (or a policy denial). ──────────────────────
async function tokenExchange(idToken, audience, resource) {
  const res = await postForm(`${config.idpUrl}/token`, {
    grant_type: oauth.GRANT_TOKEN_EXCHANGE,
    requested_token_type: oauth.TOKEN_TYPE_ID_JAG,
    subject_token: idToken,
    subject_token_type: oauth.TOKEN_TYPE_ID_TOKEN,
    audience,  // the Resource Authorization Server issuer (discovered)
    resource,  // the RFC 8707 MCP server id (discovered)
    scope: API_SCOPE,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
  });
  return { status: res.status, body: await res.json() };
}

// ── Step 3: RFC 7523 jwt-bearer at the MCP AS → audience-restricted access token. ─────────────────
async function jwtBearer(idJag, tokenEndpoint) {
  const res = await postForm(tokenEndpoint, { grant_type: oauth.GRANT_JWT_BEARER, assertion: idJag });
  return { status: res.status, body: await res.json() };
}

// ── Step 4a: MCP initialize handshake — both sides declare the EMA extension capability. ──────────
async function mcpInitialize(accessToken) {
  const res = await fetch(`${config.mcpServerUrl}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { extensions: { [oauth.EMA_EXTENSION_ID]: {} } },
        clientInfo: { name: 'mcp-ema-demo-client', version: '0.1.0' },
      },
    }),
  });
  return { status: res.status, body: await res.json() };
}

// ── Step 4b: call the protected MCP resource API with the Bearer token. ──────────────────────────
async function callApi(accessToken) {
  const res = await fetch(`${config.mcpServerUrl}/v1/contexts`, { headers: { authorization: `Bearer ${accessToken}` } });
  return { status: res.status, body: await res.json() };
}

// Run discovery (step 0) then sequence steps 2–4 from an ID Token. Returns
// { steps[], denied, accessToken?, apiData?, idJag? }. Each step is { title, endpoint, status, ok, body }
// so callers can render/print it uniformly.
async function runChain(idToken) {
  const steps = [];

  const disc = await discover();
  steps.push({
    title: '⓪ Discovery — 401 → PRM → AS metadata',
    endpoint: `GET ${config.mcpServerUrl}/v1/contexts (no token)`,
    status: disc.probeStatus,
    ok: disc.probeStatus === 401 && disc.emaSupported,
    body: {
      'www_authenticate': disc.wwwAuth,
      'protected_resource_metadata': disc.prm,
      'authorization_server_metadata': disc.asMeta,
      'ema_grant_profile_advertised': disc.emaSupported,
    },
  });
  if (disc.probeStatus !== 401 || !disc.emaSupported)
    return { steps, error: true, errorReason: 'discovery did not yield an EMA-capable MCP server' };

  const ex = await tokenExchange(idToken, disc.asIssuer, disc.resource);
  steps.push({ title: '② Token exchange → ID-JAG', endpoint: `POST ${config.idpUrl}/token`, status: ex.status, ok: ex.status === 200, body: ex.body });
  if (ex.status !== 200) return { steps, denied: true, deniedBody: ex.body };

  const idJag = ex.body.access_token;
  const jb = await jwtBearer(idJag, disc.asTokenEndpoint);
  steps.push({ title: '③ jwt-bearer → MCP access token', endpoint: `POST ${disc.asTokenEndpoint}`, status: jb.status, ok: jb.status === 200, body: jb.body });
  if (jb.status !== 200) return { steps, error: true };

  const accessToken = jb.body.access_token;
  const init = await mcpInitialize(accessToken);
  steps.push({ title: '④ MCP initialize (declares EMA capability)', endpoint: `POST ${config.mcpServerUrl}/mcp`, status: init.status, ok: init.status === 200, body: init.body });

  const api = await callApi(accessToken);
  steps.push({ title: '⑤ Call protected MCP API', endpoint: `GET ${config.mcpServerUrl}/v1/contexts`, status: api.status, ok: api.status === 200, body: api.body });

  return { steps, denied: false, idJag, accessToken, apiData: api.body };
}

module.exports = {
  CLIENT_ID, EMA_EXTENSION_ID: oauth.EMA_EXTENSION_ID,
  decodeJwt, beginLogin, completeLogin, headlessLogin, runChain,
};
