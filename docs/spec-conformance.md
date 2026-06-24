# Spec Conformance — MCP Enterprise-Managed Authorization (ID-JAG)

Verification of this POC against the normative specs, June 2026. Checked **claim-by-claim** against:

- **MCP EMA extension (stable)** — `io.modelcontextprotocol/enterprise-managed-authorization`,
  [ext-auth/specification/stable/enterprise-managed-authorization.mdx](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
- **ID-JAG draft** — [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant)
- **MCP core authorization** — [modelcontextprotocol.io/specification/.../authorization](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- RFC 8693 (token exchange), RFC 7523 (jwt-bearer), RFC 9068 (`at+jwt`), RFC 8707 (resource), RFC 9728 (PRM), RFC 6750.
- SEP-990 / [MCP EMA blog](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/).

**Verdict:** the **EMA / ID-JAG wire format is spec-exact (100%)** — every token-exchange parameter,
ID-JAG claim, `typ` header, response field, and capability string matches the normative spec, and I
confirmed it against a live ID-JAG minted by the running demo. **The client is now also MCP-core
complete**: it discovers the server via a 401 → PRM → AS-metadata loop, logs in with PKCE, and
validates the RFC 9207 `iss` (see "Update" below — the gaps the first pass flagged are now closed).

---

## ✅ EMA / ID-JAG extension — conformant, claim by claim

### 1. Token-exchange request (client → IdP) — `src/mcp-client/flow.js:72`
| Spec requirement | Required value | Impl | OK |
|---|---|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` | same (`oauth.GRANT_TOKEN_EXCHANGE`) | ✅ |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:id-jag` | same | ✅ |
| `subject_token` | the ID Token | the ID Token | ✅ |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` | same | ✅ |
| `audience` | **MUST** = issuer id of the **Resource Authorization Server** | `AS_ISSUER` (MCP AS issuer) | ✅ |
| `resource` | OPTIONAL; if set **MUST** = Resource Identifier of the MCP server | `RESOURCE` (MCP server id) | ✅ |
| `scope` | space-separated requested scopes | `contexts:read` | ✅ |

The IdP side (`src/mock-idp/index.js:237` `issueIdJag`) validates every one of these, returning
`invalid_request` / `invalid_target` on mismatch — including enforcing `audience === MCP_AS_ISSUER`
and `resource === MCP_RESOURCE`. The crucial `audience` (= Resource AS issuer) vs `resource`
(= RFC 8707 MCP server id) distinction — the easiest thing to get wrong — is correct.

### 2. The ID-JAG token — `src/mock-idp/index.js:286`
Spec `typ` header `oauth-id-jag+jwt`. Per ID-JAG draft §3.1 the **REQUIRED** claims are `iss, sub,
aud, client_id, jti, exp, iat`; `resource`, `scope`, and `email` are **OPTIONAL** (the EMA profile
adds only that, if present, `resource` **MUST** be the MCP Server's Resource Identifier). The demo
mints all of them. **Live token captured from the running demo (eve):**

```
header:  { alg: RS256, kid: …, typ: "oauth-id-jag+jwt" }
payload: { jti, iss: http://localhost:3010, sub, email: eve@example.com,
           aud: http://localhost:3001, resource: http://localhost:3001,
           client_id: mcp-client-demo, scope: "contexts:read", iat, exp }
```

| Claim | Spec | Impl | OK |
|---|---|---|---|
| `typ` (header) | `oauth-id-jag+jwt` | `oauth-id-jag+jwt` | ✅ |
| `iss` | IdP issuer | `http://localhost:3010` | ✅ |
| `sub` | end-user subject | from ID Token | ✅ |
| `aud` | **MUST** = Resource **Authorization Server** issuer | MCP AS issuer (`:3001`) | ✅ |
| `resource` | OPTIONAL; MCP server id | `:3001` | ✅ |
| `client_id` | client id at the Resource AS | `mcp-client-demo` | ✅ |
| `jti`, `exp`, `iat` | present | present (`exp` = +5m) | ✅ |
| `scope` | OPTIONAL | granted (requested ∩ allowed) | ✅ |
| `email` | OPTIONAL (account linking) | present | ✅ |

> Note: in this POC the MCP server is **both** AS and RS, so `aud` and `resource` coincide at
> `:3001`. The code documents this (`src/mock-idp/index.js:28`). In a split deployment `aud` would be
> the MCP AS issuer and `resource` the RS id — the code already keeps them as separate values, so it
> would stay conformant if the two URLs diverged.

### 3. Token-exchange response (IdP → client) — `src/mock-idp/index.js:302`
| Field | Spec | Impl | OK |
|---|---|---|---|
| `issued_token_type` | `urn:ietf:params:oauth:token-type:id-jag` | same | ✅ |
| `access_token` | carries the ID-JAG (historical RFC 8693 field name) | the ID-JAG | ✅ |
| `token_type` | `N_A` ("not an OAuth access token") | `N_A` | ✅ |
| `scope`, `expires_in` | present | `contexts:read`, `300` | ✅ |

### 4. jwt-bearer (client → MCP AS) — `src/mcp-client/flow.js:88`, `src/mcp-server/index.js:116`
| Item | Spec | Impl | OK |
|---|---|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:jwt-bearer` | same | ✅ |
| `assertion` | the ID-JAG | the ID-JAG | ✅ |
| AS validation | verify JWT sig vs **IdP JWKS**, check `aud`, `iss`, `exp` | `jwtVerify(assertion, IDP_JWKS, {typ, issuer, audience})` | ✅ |
| extra | check `resource` claim targets this server | enforced (`:138`) | ✅ |
| issued token | audience-restricted access token | `typ: at+jwt` (RFC 9068), `aud` = resource | ✅ |

The AS has **no `authorization_endpoint`** and the client never redirects to one. This isn't an
explicit spec prohibition — it's emergent: the spec's token-acquisition flow obtains the access token
entirely via token-exchange (at the IdP) + jwt-bearer (at the Resource AS *token* endpoint), with the
only front-channel redirect being to the *IdP's* authorization endpoint for login. So there is no
front-channel redirect to the Resource AS at all. `response_types_supported: []` makes the absence
explicit in metadata.

### 5. `initialize` capability — `src/mcp-client/flow.js:106`, `src/mcp-server/index.js:238`
The **EMA stable spec does not define** an MCP `initialize` / `capabilities` declaration — it covers
only the OAuth/ID-JAG wire format. The demo surfaces the extension through MCP's general
`capabilities.extensions` mechanism, keyed by the EMA extension's registered identifier:
```json
{ "capabilities": { "extensions": { "io.modelcontextprotocol/enterprise-managed-authorization": {} } } }
```
Client sends it; server echoes it in `result.capabilities.extensions`. This is a sensible convention
for advertising the extension in the handshake, **not** a spec-mandated requirement. ✅

### 6. Discovery surface
| Surface | Spec | Impl | OK |
|---|---|---|---|
| AS metadata advertises id-jag profile | `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]` | present on **both** IdP `/.well-known/openid-configuration` and MCP AS `/.well-known/oauth-authorization-server` | ✅ |
| MCP server PRM (RFC 9728) | `/.well-known/oauth-protected-resource` with `authorization_servers`, `scopes_supported`, `bearer_methods_supported` | present (`src/mcp-server/index.js:173`) | ✅ |
| RFC 6750 challenge | `WWW-Authenticate: Bearer … resource_metadata=…`; `insufficient_scope` → 403 | present (`challenge()`), incl. `scope=` on 403 | ✅ |

---

## ✅ Update — MCP-core client completeness (gaps now closed)

The first pass flagged that the *client* skipped MCP-core discovery. Those gaps are now implemented
and verified end to end (headless + browser, eve allowed / bob denied):

1. **401 → PRM → AS-metadata discovery — CLOSED.** `discover()` (`src/mcp-client/flow.js`) probes
   `GET /v1/contexts` with no token, parses `resource_metadata` from the RFC 6750 `WWW-Authenticate`
   challenge, fetches the PRM (RFC 9728) → `authorization_servers`, then the AS metadata (RFC 8414),
   and confirms `authorization_grant_profiles_supported` contains the id-jag profile. The discovered
   `resource` / AS issuer / token endpoint **drive** the token-exchange and jwt-bearer steps — they
   are no longer read from config. Surfaced in the UI as step **⓪**.
2. **RFC 9207 `iss` — CLOSED.** The mock IdP advertises `authorization_response_iss_parameter_supported:
   true`, includes `iss` on the `/login` redirect, and the client validates it with simple string
   comparison (RFC 3986 §6.2.1) for both browser and headless paths — rejecting on absence/mismatch.
3. **PKCE (S256) — CLOSED.** The client generates a verifier + S256 challenge, sends `code_challenge`
   on `/authorize`, and `code_verifier` on the token request; the IdP **requires** PKCE at `/authorize`
   and `/login` and verifies `SHA256(code_verifier) == code_challenge` at the token endpoint.
4. **EMA trigger is now discovery-driven**, not hardcoded: the client decides to run the EMA chain
   because discovery returned a 401 + an AS advertising the id-jag grant profile.

### Remaining by-design notes (not violations)
- **`resource` param on the login leg.** The IdP login yields an *identity* (ID Token), not a
  resource-bound access token; the RFC 8707 resource binding is applied where it belongs — the
  **ID-JAG exchange** (`audience` + `resource`, both now sourced from discovery) and carried as the
  ID-JAG `resource` claim. So there's no separate `resource` param on the OIDC login request.
- **SAML subject tokens not supported.** Spec allows `subject_token_type` = ID Token **or** SAML; the
  demo supports ID Token only — a documented subset.

---

## Bottom line

- **ID-JAG / EMA extension: 100% conformant** to the stable spec + IETF draft, verified against a live
  token — parameters, claims (required + optional), `typ`, `N_A`, audience-vs-resource binding, and
  discovery profile all exact. (The `initialize` `capabilities.extensions` declaration is a sensible
  handshake convention, not part of the EMA stable spec — see §5.)
- **MCP-core authorization: client and server are now both conformant** — server: PRM, RFC 6750
  challenges, audience-restricted `at+jwt`, scope enforcement; client: 401→PRM→AS-metadata discovery,
  PKCE, RFC 9207 `iss`. In short: a **spec-exact ID-JAG core on top of a MCP-core-complete client**,
  with the only documented subset being ID-Token-only (no SAML).
