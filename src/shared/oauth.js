// Exact OAuth / ID-JAG URN strings, in one place.
//
// These are the easy-to-get-subtly-wrong strings in the flow (token-exchange `token_type: N_A`, the
// `…:token-type:id-jag` vs `…:grant-type:…` namespaces, the custom JWT `typ`). Both the IdP (which
// MINTS the ID-JAG) and the MCP AS (which VALIDATES it) import from here, so there is a single source
// of truth and no chance of a typo drifting between services.
//
// Pinned spec revisions (re-verify before publishing — these are IETF drafts):
//   • ID-JAG: draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026)
//   • MCP Enterprise-Managed Authorization (SEP-990), stable profile
//   • RFC 8693 (token exchange), RFC 7523 (JWT bearer assertion)

module.exports = {
  // RFC 8693 token exchange — the grant the client uses at the IdP to get an ID-JAG.
  GRANT_TOKEN_EXCHANGE: 'urn:ietf:params:oauth:grant-type:token-exchange',
  // RFC 7523 JWT bearer — the grant the client uses at the MCP AS to redeem the ID-JAG (Phase 3).
  GRANT_JWT_BEARER: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
  // OIDC authorization_code (Phase 1 login).
  GRANT_AUTHORIZATION_CODE: 'authorization_code',

  // Token type URNs (RFC 8693 §3 + the ID-JAG draft).
  TOKEN_TYPE_ID_JAG: 'urn:ietf:params:oauth:token-type:id-jag',
  TOKEN_TYPE_ID_TOKEN: 'urn:ietf:params:oauth:token-type:id_token',
  TOKEN_TYPE_ACCESS_TOKEN: 'urn:ietf:params:oauth:token-type:access_token',

  // The token-exchange response sets token_type to this literal — an ID-JAG is NOT an access token.
  TOKEN_TYPE_NA: 'N_A',

  // The custom JWT `typ` header that marks a JWT as an ID-JAG.
  ID_JAG_TYP: 'oauth-id-jag+jwt',

  // AS-metadata value advertising the ID-JAG authorization-grant profile (the EMA discovery surface).
  GRANT_PROFILE_ID_JAG: 'urn:ietf:params:oauth:grant-profile:id-jag',

  // MCP extension id the client/server declare in the `initialize` capabilities to negotiate EMA.
  EMA_EXTENSION_ID: 'io.modelcontextprotocol/enterprise-managed-authorization',
};
