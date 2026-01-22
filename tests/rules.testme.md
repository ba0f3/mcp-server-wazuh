# TESTME: Security Rules Tools

Tests for Wazuh security rules summary retrieval.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Manager API is accessible
- Wazuh system has security rules configured

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_API_PORT | 55000 | Wazuh Manager port |

## Tests

### Rules Summary

### Test: Get security rules summary

1. Connect to the MCP server
2. Call `get_wazuh_rules_summary` tool with no arguments

**Expect:**
- Statistical summary of security rules is returned
- Summary includes information about active rules
- Response format is readable JSON or text
- Summary provides relevant statistical information

---

### Test: Rules summary includes rule statistics

1. Call `get_wazuh_rules_summary` tool
2. Inspect the response

**Expect:**
- Response includes rule counts or statistics
- Statistics reflect active security rules
- Response format is readable

---

### Edge Cases

### Test: Handle rules summary when no rules exist

1. If possible, test with a Wazuh system that has no rules configured
2. Call `get_wazuh_rules_summary` tool

**Expect:**
- Tool returns appropriate response (may show zero rules or empty summary)
- Response is not an error
- Response format is valid

---

### Test: Handle Wazuh Manager API errors

1. Temporarily make Wazuh Manager API unreachable
2. Call `get_wazuh_rules_summary` tool

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running
- Tool works again when Manager is available

---

### Test: Handle malformed rules data

1. If possible, simulate malformed rules data in Wazuh
2. Call `get_wazuh_rules_summary` tool

**Expect:**
- Tool handles malformed data gracefully
- Server does not crash
- Response is still readable (may show partial data)

---

## Teardown

1. Restore Wazuh Manager connectivity if disrupted
2. Close MCP client connections
