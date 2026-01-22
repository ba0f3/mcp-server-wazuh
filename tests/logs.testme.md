# TESTME: Log Management Tools

Tests for Wazuh manager log searching, error log retrieval, and connection validation.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Manager API is accessible
- Wazuh manager has generated logs (for positive test cases)

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_API_PORT | 55000 | Wazuh Manager port |

## Tests

### Manager Log Search

### Test: Search manager logs with query

1. Connect to the MCP server
2. Call `search_wazuh_manager_logs` tool with query parameter set to "error"

**Expect:**
- Log entries matching the query are returned
- Response includes log entries containing "error"
- Default limit of 100 results is applied
- Response format is readable JSON or text

---

### Test: Search manager logs with custom limit

1. Call `search_wazuh_manager_logs` tool with:
   - query: "authentication"
   - limit: 20

**Expect:**
- At most 20 log entries are returned
- Response contains no more than 20 entries
- All entries match the search query
- Response format is readable

---

### Test: Search manager logs with specific term

1. Call `search_wazuh_manager_logs` tool with query set to a known log term

**Expect:**
- Log entries matching the term are returned
- Response includes relevant log entries
- Response format is readable

---

### Test: Search manager logs with empty query

1. Call `search_wazuh_manager_logs` tool with query set to empty string

**Expect:**
- Tool either returns all logs (up to limit) or validates and requires a query
- If query is required, error message is clear
- Server does not crash

---

### Error Log Retrieval

### Test: Get manager error logs with default limit

1. Call `get_wazuh_manager_error_logs` tool with no arguments

**Expect:**
- Only error-level logs are returned
- Default limit of 50 results is applied
- All returned logs are error-level
- Response format is readable JSON or text

---

### Test: Get manager error logs with custom limit

1. Call `get_wazuh_manager_error_logs` tool with limit set to 10

**Expect:**
- At most 10 error logs are returned
- All returned logs are error-level
- Response contains no more than 10 entries

---

### Test: Get error logs when none exist

1. If possible, test with a system that has no error logs
2. Call `get_wazuh_manager_error_logs` tool

**Expect:**
- Tool returns appropriate response (empty list or message)
- Response is not an error
- Message is user-friendly

---

### Connection Validation

### Test: Validate Wazuh connection successfully

1. Call `validate_wazuh_connection` tool with no arguments

**Expect:**
- Connection validation is performed
- Response indicates connection is valid
- Response includes authentication status
- Response format is readable JSON or text

---

### Test: Connection validation detects invalid credentials

1. Temporarily set invalid WAZUH_API_USERNAME or WAZUH_API_PASSWORD
2. Restart the server or reconnect
3. Call `validate_wazuh_connection` tool

**Expect:**
- Tool returns an error response
- Error message indicates authentication failure
- Response clearly indicates connection validation failed

---

### Test: Connection validation detects unreachable API

1. Temporarily make Wazuh Manager API unreachable
2. Call `validate_wazuh_connection` tool

**Expect:**
- Tool returns an error response
- Error message indicates connection failure
- Response clearly indicates validation failed

---

### Edge Cases

### Test: Handle very large log search results

1. Call `search_wazuh_manager_logs` tool with a query that matches many logs
2. Use default limit (100)

**Expect:**
- Tool respects the limit
- Response contains at most 100 entries
- Response format is valid

---

### Test: Handle invalid limit values

1. Call `search_wazuh_manager_logs` tool with limit set to -1

**Expect:**
- Tool either validates and uses default or returns an error
- Error message is clear if validation fails
- Server does not crash

---

### Test: Handle Wazuh Manager API errors

1. Temporarily make Wazuh Manager API unreachable
2. Call `search_wazuh_manager_logs` tool

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running
- Tool works again when Manager is available

---

### Test: Handle malformed log data

1. If possible, simulate malformed log data in Wazuh
2. Call `search_wazuh_manager_logs` tool

**Expect:**
- Tool handles malformed data gracefully
- Server does not crash
- Response is still readable (may skip malformed entries)

---

## Teardown

1. Restore Wazuh Manager connectivity if disrupted
2. Restore original credentials if modified
3. Close MCP client connections
