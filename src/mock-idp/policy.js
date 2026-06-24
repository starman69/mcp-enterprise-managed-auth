// ─────────────────────────────────────────────────────────────────────────────
// Policy engine — the heart of Enterprise-Managed Authorization.
//
// This is the gate that makes EMA "enterprise-managed": the IdP, not the MCP server, decides whether
// a given user may obtain an ID-JAG for a given resource and scopes. Flip a rule here (or, in the
// real world, a Conditional Access policy in Entra) and the *next* token-exchange is denied — no
// redeploy of the MCP server, no per-server consent screen.
//
// This mock is deliberately a simple group→resource→scope allowlist so every decision is easy to
// follow. A real enterprise uses its IdP's conditional-access / governance engine; the shape of the
// decision (allow/deny + granted scopes, keyed on directory groups) is the same.
// ─────────────────────────────────────────────────────────────────────────────

const config = require('../shared/config');

// Resource Identifier (RFC 8707) of the MCP server this POC protects. The mcp-server plays both the
// Authorization Server and the Resource Server, so its AS issuer and its resource id coincide here.
const MCP_RESOURCE = config.resource;

// Per-resource rules: which directory groups may access it, and which scopes are grantable there.
const POLICIES = {
  [MCP_RESOURCE]: {
    allowGroups: ['mcp-users'], // eve is in this group; bob (contractors) is not
    allowedScopes: ['contexts:read', 'contexts:write'],
  },
};

/**
 * Decide whether to issue an ID-JAG.
 *
 * @param {object}   subject
 * @param {string}   subject.sub        Authenticated user id (for logging/audit).
 * @param {string[]} subject.groups     The user's directory groups (from the ID Token).
 * @param {string}   subject.resource   `resource` param — RFC 8707 id of the MCP server.
 * @param {string}   [subject.scope]    Space-delimited requested scopes (empty ⇒ "all allowed").
 * @returns {{allow: boolean, reason: string, scope?: string}}
 *          On allow, `scope` is the space-delimited GRANTED scope (requested ∩ allowed).
 */
function evaluate({ sub, groups = [], resource, scope = '' }) {
  const policy = POLICIES[resource];
  if (!policy) {
    return { allow: false, reason: `no policy for resource "${resource}" (unknown MCP server)` };
  }

  const matched = groups.filter((g) => policy.allowGroups.includes(g));
  if (matched.length === 0) {
    return {
      allow: false,
      reason: `user ${sub} is not a member of any group permitted for ${resource} ` +
        `(needs one of [${policy.allowGroups.join(', ')}]; has [${groups.join(', ')}])`,
    };
  }

  // Grant the intersection of requested and allowed scopes; if none requested, grant all allowed.
  const requested = scope.trim() ? scope.trim().split(/\s+/) : policy.allowedScopes;
  const granted = requested.filter((s) => policy.allowedScopes.includes(s));
  if (granted.length === 0) {
    return {
      allow: false,
      reason: `none of the requested scopes [${requested.join(', ')}] are allowed for ${resource} ` +
        `(allowed: [${policy.allowedScopes.join(', ')}])`,
    };
  }

  return { allow: true, reason: `allowed via group(s) [${matched.join(', ')}]`, scope: granted.join(' ') };
}

module.exports = { evaluate, POLICIES, MCP_RESOURCE };
