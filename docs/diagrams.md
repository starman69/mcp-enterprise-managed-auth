# Diagrams — MCP Enterprise-Managed Authorization (ID-JAG) POC

Visual reference for the architecture and every sequence in the flow. The fenced `mermaid` blocks
below render directly on GitHub; the raw sources also live as `.mmd` files under
[`docs/diagrams/`](diagrams/) for generating images (e.g. `mmdc -i docs/diagrams/architecture.mmd -o architecture.svg`).

Legend: **✅ built** (Phases 1–5 + MCP-core completeness — the full demo runs end to end). The headline
of the demo is that there is **no redirect to the MCP authorization endpoint** — access is decided
centrally by the IdP's policy engine during the token exchange (step ②). The client is also
**MCP-core complete**: it discovers the server via a 401 → PRM → AS-metadata loop (step ⓪) and logs in
with PKCE + RFC 9207 `iss` validation.

Pinned specs: ID-JAG `draft-ietf-oauth-identity-assertion-authz-grant-04` (21 May 2026) ·
MCP Enterprise-Managed Authorization (SEP-990) · RFC 8693 (token exchange) · RFC 7523 (JWT bearer) ·
RFC 9728 (Protected Resource Metadata) · RFC 8414 (AS metadata) · RFC 7636 (PKCE) · RFC 9207 (`iss`).

---

## 1. High-level architecture

Three Node/Express services. The MCP server plays both Authorization Server (AS) and Resource Server
(RS); its AS-issuer and resource identifier coincide in this POC. Dotted arrows are signature
validation against a published JWKS.

```mermaid
flowchart LR
  user([User])

  subgraph client["mcp-client &nbsp;:3000"]
    orch["orchestrator<br/>+ MCP initialize<br/>(declares EMA capability)"]
  end

  subgraph idp["mock-idp &nbsp;:3010 — Enterprise IdP"]
    login["/authorize + /login<br/>OIDC login (PKCE + RFC 9207 iss)<br/>→ ID Token"]
    tx["/token<br/>RFC 8693 token-exchange<br/>→ ID-JAG"]
    policy["policy engine<br/>group → resource → scope"]
    idpjwks["/jwks.json"]
  end

  subgraph server["mcp-server &nbsp;:3001 — MCP AS + RS"]
    as["AS · /oauth/token<br/>RFC 7523 jwt-bearer<br/>+ AS metadata (id-jag profile)"]
    rs["RS · /.well-known/oauth-protected-resource (PRM)<br/>protected /v1/* (401 → discovery)"]
    srvjwks["/jwks.json"]
  end

  orch -.->|"⓪ probe → 401 → PRM → AS metadata"| rs
  user -->|SSO login| login
  orch -->|"① ID Token (PKCE + iss)"| login
  orch -->|"② token-exchange · subject_token = ID Token"| tx
  tx --> policy
  policy -->|allow / deny| tx
  tx -->|"ID-JAG"| orch
  orch -->|"③ jwt-bearer · assertion = ID-JAG"| as
  as -.->|"validate ID-JAG signature"| idpjwks
  as -->|"audience-restricted access token"| orch
  orch -->|"④ Bearer access token"| rs
  rs -.->|"validate access-token signature"| srvjwks
  rs -->|"protected data"| orch

  classDef done fill:#dcfce7,stroke:#16a34a,color:#14532d;
  classDef todo fill:#fef9c3,stroke:#ca8a04,color:#713f12;
  class login,tx,policy,idpjwks,as,srvjwks,rs done;
```

---

## 2. End-to-end ID-JAG chain (headline flow)

The full chain, all built. Step ⓪ is MCP-core discovery; ①–④ are the EMA legs. The MCP server is both
AS and RS (its AS-issuer and resource id coincide here).

```mermaid
sequenceDiagram
  autonumber
  actor U as User
  participant C as mcp-client :3000
  participant I as mock-idp :3010<br/>Enterprise IdP
  participant S as mcp-server :3001<br/>MCP AS + RS

  rect rgba(59,130,246,0.12)
  Note over C,S: ⓪ Discovery — 401 → PRM → AS metadata ✅
  C->>S: GET /v1/contexts (no token)
  S-->>C: 401 · WWW-Authenticate: Bearer resource_metadata="…/oauth-protected-resource"
  C->>S: GET /.well-known/oauth-protected-resource (RFC 9728)
  S-->>C: { resource, authorization_servers:[MCP AS] }
  C->>S: GET /.well-known/oauth-authorization-server (RFC 8414)
  S-->>C: { issuer, token_endpoint, authorization_grant_profiles_supported:[id-jag] }
  Note over C: learns resource + AS + that EMA (id-jag) is required — nothing hardcoded
  end

  rect rgba(34,197,94,0.12)
  Note over U,I: ① SSO login — OIDC authorization_code + PKCE ✅ Phase 1
  U->>C: start
  C->>I: GET /authorize (response_type=code, code_challenge=S256)
  I-->>U: login form
  U->>I: POST /login (credentials)
  I-->>C: 302 redirect ?code=…&iss=… (RFC 9207)
  Note over C: validate iss == IdP issuer (RFC 9207)
  C->>I: POST /token (grant_type=authorization_code, code_verifier)
  I->>I: verify PKCE (S256)
  I-->>C: ID Token (signed JWT)
  end

  rect rgba(34,197,94,0.12)
  Note over C,I: ② Token exchange → ID-JAG — RFC 8693 ✅ Phase 2
  C->>I: POST /token · grant_type=token-exchange<br/>subject_token=ID Token · requested_token_type=id-jag<br/>audience=MCP AS · resource=MCP server
  I->>I: verify ID Token, then EVALUATE POLICY
  alt policy allows
    I-->>C: ID-JAG (typ: oauth-id-jag+jwt) · token_type: N_A
  else policy denies
    I-->>C: 403 access_denied
  end
  end

  rect rgba(34,197,94,0.12)
  Note over C,S: ③ jwt-bearer → access token — RFC 7523 ✅ Phase 3
  C->>S: POST /oauth/token · grant_type=jwt-bearer · assertion=ID-JAG
  S->>I: GET /jwks.json (fetch IdP keys)
  S->>S: validate ID-JAG sig · typ · iss · aud · exp · resource
  S-->>C: access token (typ at+jwt, audience-restricted to the MCP server)
  end

  rect rgba(34,197,94,0.12)
  Note over C,S: ④ Use the MCP server — initialize + protected call ✅ Phases 4–5
  C->>S: POST /mcp · initialize (Bearer token)<br/>capabilities.extensions[enterprise-managed-authorization]
  S-->>C: serverInfo + capabilities (EMA extension declared)
  C->>S: GET /v1/contexts · Authorization: Bearer <access token>
  S->>S: validate token (sig · iss · aud = this MCP server · exp · scope)
  S-->>C: 200 protected data
  end

  Note over C,S: No redirect to the MCP authorization endpoint —<br/>access is decided centrally by the IdP policy engine at step ②.<br/>Client orchestrates the whole chain (Phase 5: browser + `npm run demo`).
```

---

## 3. Phase 1 — OIDC login → ID Token (built)

The ordinary OIDC `authorization_code` leg. Its only job is to produce an **ID Token**; the `groups`
claim it carries is what the Phase-2 policy engine decides on.

```mermaid
sequenceDiagram
  autonumber
  actor U as User
  participant C as mcp-client :3000
  participant I as mock-idp :3010 (IdP)
  participant K as IdP keystore<br/>(RS256, ephemeral)

  Note over I,K: at startup: generate keypair, kid = RFC 7638 thumbprint,<br/>publish public JWK at /jwks.json

  Note over C: generate PKCE verifier + S256 challenge · record expected issuer

  C->>I: GET /authorize?response_type=code&client_id=…&redirect_uri=…&scope=openid…&nonce=…<br/>&code_challenge=…&code_challenge_method=S256
  I->>I: validate client_id + redirect_uri + require PKCE (S256)
  I-->>U: render login form (carries the OAuth params incl. code_challenge)
  U->>I: POST /login (username, password, + params)
  alt bad credentials
    I-->>U: 401 + re-rendered form
  else valid
    I->>I: mint one-time auth code → store {sub, nonce, scope, code_challenge, exp 60s}
    I-->>C: 302 redirect_uri?code=…&state=…&iss=… (RFC 9207)
  end

  Note over C: validate iss == recorded IdP issuer (RFC 9207, simple string compare)

  C->>I: POST /token (grant_type=authorization_code, code, client_id, redirect_uri, code_verifier)
  I->>I: consume code (single use), check client/redirect/exp,<br/>verify PKCE: SHA256(code_verifier) == code_challenge
  I->>K: sign ID Token (RS256, kid in header)
  I-->>C: { id_token, access_token, token_type, expires_in }

  Note over C: ID Token claims: iss, sub, aud=client_id, nonce,<br/>auth_time, name, email, groups[]  ← groups feed Phase 2 policy
```

---

## 4. Phase 2 — token exchange → ID-JAG, gated by policy (built)

The core of Enterprise-Managed Authorization: the IdP, not the MCP server, decides access. `eve`
(in `mcp-users`) is allowed; `bob` (a contractor) is denied with `access_denied`. Note the exact
wire format — `token_type: "N_A"` and the `oauth-id-jag+jwt` header.

```mermaid
sequenceDiagram
  autonumber
  participant C as mcp-client :3000
  participant I as mock-idp /token
  participant P as policy engine
  participant K as IdP keystore

  C->>I: POST /token (form-encoded)<br/>grant_type = …:grant-type:token-exchange<br/>requested_token_type = …:token-type:id-jag<br/>subject_token = ID Token<br/>subject_token_type = …:token-type:id_token<br/>audience = MCP AS issuer · resource = MCP server id<br/>scope = contexts:read · client_id + client_secret

  I->>I: 1. authenticate client (client_id + client_secret)
  I->>I: 2. validate URNs + audience/resource targets
  I->>K: 3. verify subject_token (ID Token) signature, iss, aud, exp
  K-->>I: claims {sub, email, groups[]}

  I->>P: 4. evaluate({sub, groups, resource, scope})
  alt user in an allowed group (e.g. eve ∈ mcp-users)
    P-->>I: allow + granted scope (requested ∩ allowed)
    I->>K: 5. sign ID-JAG · header typ = oauth-id-jag+jwt<br/>claims: jti, iss, sub, email, aud, resource, client_id, scope, iat, exp(5m)
    K-->>I: ID-JAG
    I-->>C: 200 { issued_token_type=…:id-jag,<br/>access_token=ID-JAG, token_type="N_A",<br/>scope, expires_in:300 }
  else user not in an allowed group (e.g. bob ∈ contractors)
    P-->>I: deny + reason
    I-->>C: 403 { error: "access_denied", error_description }
  end
```

---

## 5. Phase 3 — jwt-bearer → audience-restricted access token (built)

The MCP Authorization Server redeems the ID-JAG (RFC 7523 `jwt-bearer`) for a short-lived MCP access
token. It runs no login or consent — it trusts the IdP's signature and policy decision, validates
the ID-JAG against the IdP's JWKS, and audience-restricts the issued token (`aud` = MCP server,
`typ: at+jwt`) so the Resource Server accepts it only for itself.

```mermaid
sequenceDiagram
  autonumber
  participant C as mcp-client :3000
  participant S as mcp-server /oauth/token<br/>(MCP AS)
  participant J as IdP JWKS<br/>:3010/jwks.json
  participant K as MCP AS keystore

  C->>S: POST /oauth/token (form-encoded)<br/>grant_type = …:grant-type:jwt-bearer<br/>assertion = ID-JAG

  S->>S: 1. require grant_type=jwt-bearer + assertion present
  S->>J: 2. fetch IdP public keys (cached)
  J-->>S: JWKS
  S->>S: 3. jwtVerify(ID-JAG): signature + typ=oauth-id-jag+jwt<br/>+ iss=IdP + aud=this AS + exp
  S->>S: 4. check resource claim == this MCP server (RFC 8707)
  S->>S: 5. intersect ID-JAG scope with server-supported scopes

  alt all checks pass
    S->>K: 6. sign access token (typ at+jwt)<br/>iss=AS, sub, aud=resource (MCP server), client_id, scope, jti, exp(15m)
    K-->>S: access token
    S-->>C: 200 { access_token, token_type: "Bearer", expires_in: 900, scope }
  else signature / typ / iss / aud / exp invalid
    S-->>C: 400 { error: "invalid_grant" }
  else resource not this server
    S-->>C: 400 { error: "invalid_target" }
  end

  Note over C,S: The access token is audience-restricted (aud = MCP server) — the Resource Server<br/>(Phase 4) accepts it only if aud matches itself.
```

---

## 6. Phase 4 — Resource Server: validate token, serve protected data (built)

The Resource Server enforces the audience restriction the AS applied: a token is honoured only if its
`aud` is this server. Failures return RFC 6750 `WWW-Authenticate` challenges carrying the RFC 9728
`resource_metadata` pointer, so a client can discover the right Authorization Server.

```mermaid
sequenceDiagram
  autonumber
  participant C as mcp-client :3000
  participant R as mcp-server /v1/*<br/>(MCP RS)
  participant K as MCP AS keystore<br/>(= AS JWKS)

  Note over C,R: The client reaches this RS via step ⓪ discovery: an unauthenticated probe returns 401,<br/>and GET /.well-known/oauth-protected-resource (RFC 9728) → { resource, authorization_servers, scopes_supported }

  C->>R: GET /v1/contexts<br/>Authorization: Bearer <access token>

  alt no Authorization header
    R-->>C: 401 · WWW-Authenticate: Bearer error="invalid_request",<br/>resource_metadata="…/oauth-protected-resource"
  else token present
    R->>K: verify signature (RFC 9068 typ at+jwt)
    R->>R: check iss = AS · aud = THIS server · exp
    alt signature / iss / aud / exp invalid
      R-->>C: 401 · WWW-Authenticate: Bearer error="invalid_token", resource_metadata="…"
    else valid but missing required scope
      R-->>C: 403 · WWW-Authenticate: Bearer error="insufficient_scope", scope="contexts:read"
    else valid + scope contexts:read
      R-->>C: 200 { sub, count, contexts[] }
    end
  end
```
