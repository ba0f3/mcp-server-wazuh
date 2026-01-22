# TESTME: Wazuh MCP Server Integration

End-to-end integration tests for the Wazuh MCP Server, covering server initialization, connection validation, tool discovery, and core functionality verification.

## Prerequisites

- Go 1.25 or higher is installed
- Wazuh Manager API is accessible and running (v4.12 recommended)
- Wazuh Indexer API is accessible and running
- Network connectivity to Wazuh Manager and Indexer endpoints
- Valid Wazuh API credentials

## Setup

1. Ensure all required environment variables are set (see Environment section)
2. Verify Wazuh Manager API is accessible at `WAZUH_API_HOST:WAZUH_API_PORT`
3. Verify Wazuh Indexer API is accessible at `WAZUH_INDEXER_HOST:WAZUH_INDEXER_PORT`
4. Build the server: `go build -o mcp-server-wazuh ./cmd/mcp-server-wazuh`
5. Verify the binary exists and is executable

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager API hostname or IP |
| WAZUH_API_PORT | 55000 | Wazuh Manager API port |
| WAZUH_API_USERNAME | wazuh | Wazuh Manager API username |
| WAZUH_API_PASSWORD | wazuh | Wazuh Manager API password |
| WAZUH_INDEXER_HOST | localhost | Wazuh Indexer API hostname or IP |
| WAZUH_INDEXER_PORT | 9200 | Wazuh Indexer API port |
| WAZUH_INDEXER_USERNAME | admin | Wazuh Indexer API username |
| WAZUH_INDEXER_PASSWORD | admin | Wazuh Indexer API password |
| WAZUH_VERIFY_SSL | false | Verify SSL certificates (true/false) |
| MCP_SERVER_TRANSPORT | stdio | Transport mode (stdio or http) |

## Tests

### Server Initialization

### Test: Server starts successfully with valid configuration

1. Set all required environment variables (WAZUH_API_HOST, WAZUH_API_PORT, WAZUH_API_USERNAME, WAZUH_API_PASSWORD, WAZUH_INDEXER_HOST, WAZUH_INDEXER_PORT, WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD)
2. Run the server: `./mcp-server-wazuh` (or via MCP client)
3. Wait for server to initialize (up to 5 seconds)

**Expect:**
- Server starts without errors
- No fatal errors in stderr
- Server is ready to accept MCP protocol requests

---

### Test: Server fails with missing required environment variables

1. Unset WAZUH_API_HOST environment variable
2. Run the server: `./mcp-server-wazuh`
3. Observe the output

**Expect:**
- Server exits with non-zero exit code
- Error message indicates configuration failure
- Server does not start successfully

---

### Connection Validation

### Test: Server validates Wazuh Manager connection

1. Start the server with valid configuration
2. Connect an MCP client to the server
3. Call the `validate_wazuh_connection` tool

**Expect:**
- Tool returns success status
- Response indicates connection is valid
- No authentication errors

---

### Test: Server handles invalid Wazuh credentials

1. Set WAZUH_API_USERNAME to an invalid username
2. Set WAZUH_API_PASSWORD to an invalid password
3. Start the server
4. Connect an MCP client
5. Call any tool that requires Wazuh Manager API access (e.g., `get_wazuh_agents`)

**Expect:**
- Tool returns an error response
- Error message indicates authentication failure
- Server does not crash

---

### Tool Discovery

### Test: All 29 tools are registered and discoverable

1. Start the server with valid configuration
2. Connect an MCP client
3. List all available tools

**Expect:**
- Exactly 29 tools are available
- Tools include: `get_wazuh_alerts`, `get_wazuh_agents`, `get_wazuh_vulnerabilities`, `validate_wazuh_connection`, etc.
- Each tool has a name and description

---

### Test: Tool descriptions are present and informative

1. Start the server
2. Connect an MCP client
3. List tools and inspect descriptions

**Expect:**
- Each tool has a non-empty description
- Descriptions clearly explain what the tool does
- Tool names follow the naming convention (snake_case)

---

### Core Functionality

### Test: Server handles empty tool arguments gracefully

1. Start the server
2. Connect an MCP client
3. Call `get_wazuh_alerts` with no arguments (empty object)

**Expect:**
- Tool executes successfully
- Default values are used (e.g., limit defaults to 100)
- Response is returned (may be empty if no alerts exist)

---

### Test: Server handles invalid tool arguments

1. Start the server
2. Connect an MCP client
3. Call `get_wazuh_alerts` with invalid arguments (e.g., limit: -1 or limit: 10000)

**Expect:**
- Tool either validates and corrects the input (using defaults) or returns an error
- Server does not crash
- Error message is clear if validation fails

---

### Test: Server handles Wazuh API errors gracefully

1. Start the server
2. Connect an MCP client
3. Temporarily make Wazuh Manager API unreachable (stop service or block network)
4. Call any tool that requires Wazuh Manager API (e.g., `get_wazuh_agents`)

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running and responsive
- Server can recover when API becomes available again

---

### Test: Server handles empty responses from Wazuh

1. Start the server
2. Connect an MCP client
3. Call `get_wazuh_alerts` when no alerts exist in the system

**Expect:**
- Tool returns a message indicating no alerts found
- Response is not an error
- Message is user-friendly (e.g., "No Wazuh alerts found.")

---

### Authentication and Token Management

### Test: Server authenticates and caches token

1. Start the server
2. Connect an MCP client
3. Call `get_wazuh_agents` tool
4. Immediately call another tool (e.g., `get_wazuh_alerts`)

**Expect:**
- First tool call succeeds
- Second tool call succeeds without re-authenticating
- Token is cached and reused

---

### Test: Server re-authenticates when token expires

1. Start the server
2. Connect an MCP client
3. Wait for token to expire (or manually expire it if possible)
4. Call a tool that requires authentication

**Expect:**
- Server automatically re-authenticates
- Tool call succeeds
- New token is obtained and cached

---

### Transport Modes

### Test: Server works with stdio transport (default)

1. Set MCP_SERVER_TRANSPORT to "stdio" (or leave unset)
2. Start the server
3. Connect via stdio transport

**Expect:**
- Server starts successfully
- MCP protocol communication works over stdio
- Tools can be called and return responses

---

### Test: Server works with HTTP transport

1. Set MCP_SERVER_TRANSPORT to "http"
2. Set MCP_SERVER_HOST and MCP_SERVER_PORT (if needed)
3. Start the server
4. Connect via HTTP transport

**Expect:**
- Server starts and listens on the specified port
- MCP protocol communication works over HTTP
- Tools can be called and return responses

---

## Teardown

1. Stop the MCP server if running
2. Close any MCP client connections
3. Restore original environment variables if modified
4. Restore Wazuh API connectivity if it was disrupted for testing
