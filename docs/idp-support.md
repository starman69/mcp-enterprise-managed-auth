# IdP support for the ID-JAG / Enterprise-Managed Authorization flow (as of June 2026)

Which **publicly available identity providers** can play the IdP role in this flow today — i.e. accept
an SSO assertion and **issue an ID-JAG** (RFC 8693 token-exchange → `oauth-id-jag+jwt`) that an MCP
Authorization Server then redeems. This is the role our `mock-idp` stands in for.

> **Caveats — read first.**
> - **Pre-standard.** ID-JAG is an IETF *draft* (`draft-ietf-oauth-identity-assertion-authz-grant-04`,
>   21 May 2026). Everything below is a **draft implementation**; wire details can still shift.
> - **Two different "supports".** Distinguish (a) issuing ID-JAGs for the **MCP Enterprise-Managed
>   Authorization** extension (SEP-990) specifically, from (b) implementing the underlying
>   **Cross-App Access (XAA)** / ID-JAG grant for app-to-app access generally. An IdP can do (b)
>   without being wired into Claude/MCP's EMA program yet.
> - **Dated + moving fast.** This snapshot is **June 2026** — re-verify against each vendor's docs
>   before relying on it. Beta/waitlist status changes frequently.
> - **"Cross-App Access" (XAA)** is the common product brand for the ID-JAG grant (Okta coined it);
>   treat XAA ≈ ID-JAG at the wire level.

## Generally available for MCP Enterprise-Managed Authorization

| IdP | Status (Jun 2026) | Notes |
|---|---|---|
| **Okta** | ✅ **GA** | The **only GA enterprise IdP** for MCP EMA today, under the **Cross App Access (XAA)** brand. MCP EMA reached **stable on 2026-06-18**; Okta is the first/launch IdP. Public sandbox at **xaa.dev**; XAA "Resource App" / "Requesting App" catalog integrations in the Okta Admin Console (May 2026). ID-JAG co-author **Aaron Parecki** is at Okta. At launch, Claude provisioned 7 MCP connectors through Okta (Asana, Atlassian, Canva, Figma, Granola, Linear, Supabase). |

## Implement Cross-App Access / ID-JAG, but **not** GA for MCP EMA (beta / waitlist / general XAA)

| IdP / platform | Status (Jun 2026) | Notes |
|---|---|---|
| **Auth0** (Okta-owned) | 🧪 Beta | XAA documented (`auth0.com/docs/.../xaa`) with a sample "Requesting Application" inspector. Issues ID-JAGs in a beta program; separate product surface from Okta Workforce. |
| **Microsoft Entra ID** | 🧪 Beta / waitlist | On the EMA roadmap; **not GA**. **Important:** Entra's *productized* token exchange today is **On-Behalf-Of (OBO)**, which is **not** a spec-exact ID-JAG emitter — treat ID-JAG as the standards north star and Entra as the real IdP that already does policy-gated exchange. **Re-verify before claiming Entra mints spec-exact ID-JAGs.** (This is the target of the repo's optional **Phase 6** chapter.) |
| **Google Workspace** | 🧪 Beta / waitlist | Listed on the EMA roadmap of planned IdP integrations; no GA timeline published. |
| **Ping Identity** | 🧪 Beta | Contributor to the IETF ID-JAG draft; XAA positioning; beta. |
| **WorkOS** | 🟡 Building blocks | Provides XAA / ID-JAG primitives aimed at **AI app and agent providers** (the resource/requesting-app side as much as the IdP side). Good fit if you're building the *app* end rather than bringing a workforce IdP. |
| **Descope** | 🟡 Available | CIAM with XAA / ID-JAG support and agentic-AI guidance; more CIAM/agent-oriented than workforce-IdP. |
| **Scalekit** | 🟡 Available | Positions XAA for agentic auth flows (B2B/agent-provider oriented). |

## How this maps to the repo

- Our **`mock-idp`** is a spec-exact stand-in for the **Okta** role (issue an ID-JAG after a policy
  gate) — fully reproducible with `npm run dev`, no account needed.
- The optional **Phase 6 / Entra variant** maps onto the **Microsoft Entra (beta)** row: a real
  enterprise IdP that does policy-gated token exchange (OBO today), documented honestly as *not yet*
  a spec-exact ID-JAG emitter. Build guide: **[`docs/phase6-entra-guide.md`](phase6-entra-guide.md)**
  (incl. the [Claude EMA waitlist](https://claude.com/form/ema-waitlist) that unlocks Entra as an IdP).
- **AWS** appears nowhere above: it has **no** workforce IdP issuing ID-JAGs (IAM Identity Center
  authorizes its own permission sets, not arbitrary downstream apps; Cognito is CIAM) — a structural
  gap, not an oversight.

## Sources

- [MCP Enterprise-Managed Authorization extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization) · [MCP blog: zero-touch OAuth](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/) · [SEP-990](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/990)
- [ID-JAG IETF draft-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) · [oauth.net: Cross-App Access](https://oauth.net/cross-app-access/)
- Okta: [Cross App Access (developer blog)](https://developer.okta.com/blog/2025/09/03/cross-app-access) · [Configure Cross App Access (help)](https://help.okta.com/oie/en-us/content/topics/apps/apps-cross-app-access.htm)
- [Auth0: XAA docs](https://auth0.com/docs/secure/call-apis-on-users-behalf/xaa) · [auth0 XAA inspector sample](https://github.com/auth0-samples/auth0-cross-app-access-inspector)
- [WorkOS: ID-JAG / Cross-App Access](https://workos.com/blog/id-jag-cross-app-access) · [Descope: XAA explainer](https://www.descope.com/learn/post/id-jag-cross-app-access) · [Scalekit: XAA for agentic auth](https://www.scalekit.com/blog/cross-app-access-agentic-auth-flows)
- Launch coverage: [Claude MCP connectors via Okta (TechTimes)](https://www.techtimes.com/articles/318704/20260619/claude-mcp-connectors-now-provision-through-okta-employees-inherit-access-login.htm) · [EMA goes stable (TechTimes)](https://www.techtimes.com/articles/318708/20260619/mcp-enterprise-authorization-goes-stable-zero-touch-sso-okta-anthropic-vs-code.htm)
