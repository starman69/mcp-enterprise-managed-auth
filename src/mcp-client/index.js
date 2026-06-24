// ─────────────────────────────────────────────────────────────────────────────
// mcp-client (port 3000) — orchestrates the full Enterprise-Managed Authorization chain and narrates
// each step. Two ways to run it:
//   • Browser:  open http://localhost:3000 → sign in at the IdP → see the narrated chain.
//   • Headless: `node index.js demo` (or `npm run demo`) → runs eve (allowed) + bob (denied) and
//               prints the narration to the console. Requires the idp + server to be running.
//
// The point the demo makes: there is NO redirect to an MCP authorization endpoint. After SSO, the
// client drives token-exchange → jwt-bearer → API call directly, and the IdP's policy decides access.
// ─────────────────────────────────────────────────────────────────────────────

const express = require('express');
const config = require('../shared/config');
const flow = require('./flow');

const PORT = process.env.PORT || 3000;

// ── Console narration (headless demo) ────────────────────────────────────────────────────────────
function printChain(actor, idToken, chain) {
  const dj = flow.decodeJwt(idToken);
  console.log(`\n================ ${actor.toUpperCase()} ================`);
  console.log(`① SSO login → ID Token  (sub=${dj?.payload?.sub}, groups=[${(dj?.payload?.groups || []).join(', ')}])`);
  for (const s of chain.steps) {
    console.log(`${s.title}  → HTTP ${s.status} ${s.ok ? 'OK' : 'FAIL'}   [${s.endpoint}]`);
    if (s.title.startsWith('②') && s.ok) {
      const j = flow.decodeJwt(s.body.access_token);
      console.log(`     ID-JAG: typ=${j?.header?.typ} aud=${j?.payload?.aud} resource=${j?.payload?.resource} scope="${j?.payload?.scope}"`);
    }
    if (s.title.startsWith('③') && s.ok) {
      const j = flow.decodeJwt(s.body.access_token);
      console.log(`     access token: typ=${j?.header?.typ} aud=${j?.payload?.aud} scope="${j?.payload?.scope}"`);
    }
    if (s.title.startsWith('④') && s.ok) {
      const ext = Object.keys(s.body?.result?.capabilities?.extensions || {});
      console.log(`     server declared extensions: [${ext.join(', ')}]`);
    }
  }
  if (chain.denied) {
    console.log(`\n🚫 DENIED at the policy gate: ${chain.deniedBody?.error} — ${chain.deniedBody?.error_description}`);
  } else {
    console.log(`\n✅ ALLOWED — MCP API returned ${chain.apiData?.count} contexts.`);
  }
}

async function runDemo() {
  console.log('Headless EMA demo — running the full chain for an allowed and a denied user.');
  for (const [user] of [['eve'], ['bob']]) {
    try {
      const idToken = await flow.headlessLogin(user, 'password');
      const chain = await flow.runChain(idToken);
      printChain(user, idToken, chain);
    } catch (e) {
      console.error(`\n${user}: ERROR — ${e.message}`);
      process.exitCode = 1;
    }
  }
  console.log('\nDone.');
}

// ── Browser rendering ────────────────────────────────────────────────────────────────────────────
const esc = (s = '') =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pre = (obj) => `<pre>${esc(JSON.stringify(obj, null, 2))}</pre>`;

const PAGE_HEAD = `<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{font:15px/1.6 system-ui,sans-serif;background:#0f172a;color:#e2e8f0;max-width:820px;margin:0 auto;padding:2rem 1rem}
  a.btn{display:inline-block;background:#6366f1;color:#fff;text-decoration:none;padding:.6rem 1rem;border-radius:8px;font-weight:600}
  a.btn:hover{background:#4f46e5}
  code{background:#1e293b;padding:.1rem .35rem;border-radius:4px}
  .card{background:#1e293b;border-radius:10px;padding:1rem 1.25rem;margin:1rem 0;border-left:4px solid #334155}
  .card.ok{border-left-color:#16a34a}.card.bad{border-left-color:#dc2626}
  .badge{font-size:.75rem;font-weight:700;padding:.1rem .5rem;border-radius:999px}
  .badge.ok{background:#14532d;color:#bbf7d0}.badge.bad{background:#7f1d1d;color:#fecaca}
  .ep{color:#94a3b8;font-size:.8rem}
  pre{background:#0b1220;padding:.75rem;border-radius:7px;overflow-x:auto;font-size:.8rem;color:#cbd5e1}
  .claims{color:#a5b4fc;font-size:.82rem;margin:.4rem 0}
  .verdict{font-size:1.15rem;font-weight:700;padding:1rem 1.25rem;border-radius:10px;margin:1.25rem 0}
  .verdict.ok{background:#14532d;color:#dcfce7}.verdict.bad{background:#7f1d1d;color:#fee2e2}
  h1{font-size:1.3rem}.muted{color:#94a3b8}
</style>`;

function stepCard(s) {
  const cls = s.ok ? 'ok' : 'bad';
  let claims = '';
  if (s.title.startsWith('②') && s.ok) {
    const j = flow.decodeJwt(s.body.access_token);
    claims = `<div class="claims">ID-JAG header <code>typ=${esc(j?.header?.typ)}</code> · aud=<code>${esc(j?.payload?.aud)}</code> · resource=<code>${esc(j?.payload?.resource)}</code> · scope=<code>${esc(j?.payload?.scope)}</code></div>`;
  }
  if (s.title.startsWith('③') && s.ok) {
    const j = flow.decodeJwt(s.body.access_token);
    claims = `<div class="claims">access token <code>typ=${esc(j?.header?.typ)}</code> · aud=<code>${esc(j?.payload?.aud)}</code> · scope=<code>${esc(j?.payload?.scope)}</code></div>`;
  }
  if (s.title.startsWith('④') && s.ok) {
    const ext = Object.keys(s.body?.result?.capabilities?.extensions || {});
    claims = `<div class="claims">server capabilities.extensions: <code>${esc(ext.join(', '))}</code></div>`;
  }
  return `<div class="card ${cls}">
    <span class="badge ${cls}">HTTP ${s.status}</span> <b>${esc(s.title)}</b>
    <div class="ep">${esc(s.endpoint)}</div>${claims}${pre(s.body)}</div>`;
}

function renderResults(actor, idToken, chain) {
  const dj = flow.decodeJwt(idToken);
  const loginCard = `<div class="card ok"><span class="badge ok">OK</span> <b>① SSO login → ID Token</b>
    <div class="claims">sub=<code>${esc(dj?.payload?.sub)}</code> · email=<code>${esc(dj?.payload?.email)}</code> · groups=<code>${esc((dj?.payload?.groups || []).join(', '))}</code></div>
    <div class="claims">auth-code + <code>PKCE (S256)</code> · RFC 9207 <code>iss</code> validated</div>
    ${pre(dj?.payload)}</div>`;
  const verdict = chain.denied
    ? `<div class="verdict bad">🚫 Access DENIED at the IdP policy gate — <code>${esc(chain.deniedBody?.error)}</code><br><span class="muted">${esc(chain.deniedBody?.error_description)}</span></div>`
    : `<div class="verdict ok">✅ Access ALLOWED — the MCP server returned ${chain.apiData?.count} contexts.</div>`;
  return `<!doctype html><html><head>${PAGE_HEAD}<title>EMA chain — ${esc(actor)}</title></head><body>
    <h1>Enterprise-Managed Authorization — result for <code>${esc(actor)}</code></h1>
    <p class="muted">No redirect to an MCP authorization endpoint — after SSO the client drove the chain and the IdP's policy decided access.</p>
    ${verdict}${loginCard}${chain.steps.map(stepCard).join('')}
    <p><a class="btn" href="/">← run again</a></p></body></html>`;
}

// ── Server ───────────────────────────────────────────────────────────────────────────────────────
const sessions = new Map(); // state -> { nonce }

function main() {
  const app = express();

  app.get('/', (req, res) => {
    res.type('html').send(`<!doctype html><html><head>${PAGE_HEAD}<title>MCP EMA demo client</title>
<style>
  .hero{text-align:center;padding:2.5rem 0 1rem}
  .hero h1{font-size:1.7rem;margin:.4rem 0 .6rem;letter-spacing:-.01em}
  .tag{display:inline-block;font-size:.7rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;
    color:#a5b4fc;background:#1e293b;border:1px solid #334155;padding:.28rem .65rem;border-radius:999px}
  .lede{color:#cbd5e1;max-width:600px;margin:0 auto;font-size:1rem}
  .flow{display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:.4rem;margin:1.6rem auto 1.9rem;max-width:700px}
  .chip{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:.34rem .6rem;font-size:.8rem;white-space:nowrap}
  .chip b{color:#a5b4fc}
  .chip.gate{border-color:#6366f1;background:#312e81;color:#e0e7ff}
  .chip.gate b{color:#c7d2fe}
  .arr{color:#64748b}
  .cta{margin:.25rem 0 1.9rem}
  .users{max-width:560px;margin:0 auto;text-align:left;padding:.35rem 1.1rem}
  .users .row{display:flex;align-items:center;gap:.6rem;padding:.6rem 0}
  .users .row + .row{border-top:1px solid #334155}
</style></head><body>
  <div class="hero">
    <span class="tag">SEP-990 · ID-JAG</span>
    <h1>MCP Enterprise-Managed Authorization</h1>
    <p class="lede">Sign in once at the enterprise IdP. The client discovers the MCP server, completes
      SSO with PKCE, then drives the full ID-JAG chain — and the IdP's policy decides access.
      There is no redirect to an MCP authorization&nbsp;endpoint.</p>

    <div class="flow">
      <span class="chip"><b>⓪</b> Discover</span><span class="arr">→</span>
      <span class="chip"><b>①</b> SSO + PKCE</span><span class="arr">→</span>
      <span class="chip gate"><b>②</b> Policy gate → ID-JAG</span><span class="arr">→</span>
      <span class="chip"><b>③</b> jwt-bearer</span><span class="arr">→</span>
      <span class="chip"><b>④</b> MCP API</span>
    </div>

    <div class="cta"><a class="btn" href="/login">Sign in at Acme Corp IdP →</a></div>

    <div class="card users">
      <div class="row"><span class="badge ok">ALLOW</span> <code>eve / password</code>
        <span class="muted">— in <code>mcp-users</code></span></div>
      <div class="row"><span class="badge bad">DENY</span> <code>bob / password</code>
        <span class="muted">— a contractor, denied at the policy gate</span></div>
    </div>
  </div>
</body></html>`);
  });

  // Step 1 — discover the IdP, build a PKCE-protected authorization URL, send the user to SSO.
  app.get('/login', async (req, res) => {
    try {
      const { url, state, session } = await flow.beginLogin();
      sessions.set(state, session); // { nonce, verifier, expectedIss, issParamSupported }
      res.redirect(url);
    } catch (e) {
      res.status(500).send(`<pre>login failed: ${esc(e.message)}</pre>`);
    }
  });

  // Step 1 callback — validate RFC 9207 iss, redeem the code (with PKCE verifier) for an ID Token,
  // then run discovery + steps 2–5 and narrate.
  app.get('/callback', async (req, res) => {
    const { code, state, iss } = req.query;
    if (!state || !sessions.has(state)) return res.status(400).send('unknown or missing state');
    const session = sessions.get(state);
    sessions.delete(state);
    if (!code) return res.status(400).send('missing authorization code');
    try {
      const idToken = await flow.completeLogin({ code, returnedIss: iss, session });
      const chain = await flow.runChain(idToken);
      const actor = flow.decodeJwt(idToken)?.payload?.email || 'user';
      res.type('html').send(renderResults(actor, idToken, chain));
    } catch (e) {
      res.status(500).send(`<pre>chain failed: ${esc(e.message)}</pre>`);
    }
  });

  app.listen(PORT, () => console.log(`mcp-client running at ${config.clientUrl} (port ${PORT}); server: ${config.mcpServerUrl}, idp: ${config.idpUrl}`));
}

if (process.argv[2] === 'demo') {
  runDemo().then(() => process.exit(process.exitCode || 0));
} else {
  main();
}
