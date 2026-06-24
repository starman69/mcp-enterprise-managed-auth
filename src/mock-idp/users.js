// Trivial demo user directory for the mock enterprise IdP.
//
// In a real IdP these are workforce identities backed by a directory; `groups` stands in for the
// directory groups / app roles that the Phase-2 policy engine gates ID-JAG issuance on. We ship one
// user who is a member of `mcp-users` (the allow case) and one who is not (the deny case) so the
// "central policy decides access" story has both branches to demo.
//
// Passwords are plaintext on purpose — this is a throwaway local login, not a credential store.

module.exports = [
  {
    sub: 'd1f1c2a0-0000-4000-8000-000000000001',
    username: 'eve',
    password: 'password',
    name: 'Eve Approver',
    email: 'eve@example.com',
    groups: ['mcp-users', 'engineering'], // member of mcp-users → Phase 2 will ALLOW
  },
  {
    sub: 'd1f1c2a0-0000-4000-8000-000000000002',
    username: 'bob',
    password: 'password',
    name: 'Bob Contractor',
    email: 'bob@example.com',
    groups: ['contractors'], // NOT in mcp-users → Phase 2 will DENY
  },
];
