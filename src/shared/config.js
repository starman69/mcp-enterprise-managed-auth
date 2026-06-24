require('dotenv').config();

// Cross-service URLs. Each service also reads its own PORT from its local .env.
// dotenv.config() loads the .env of whichever service is the current working dir.
module.exports = {
  idpUrl: process.env.IDP_URL || 'http://localhost:3010',
  mcpServerUrl: process.env.MCP_SERVER_URL || 'http://localhost:3001',
  clientUrl: process.env.CLIENT_URL || 'http://localhost:3000',

  // The resource identifier (RFC 8707) the MCP access token is audience-restricted to.
  resource: process.env.MCP_RESOURCE || process.env.MCP_SERVER_URL || 'http://localhost:3001',
};
