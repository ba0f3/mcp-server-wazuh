# TESTME: Vulnerability Management Tools

Tests for vulnerability detection, filtering by severity, critical vulnerability identification, and vulnerability summaries.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Manager API is accessible
- Wazuh Indexer is accessible
- Vulnerability data exists in the Wazuh system (for positive test cases)

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_INDEXER_HOST | localhost | Wazuh Indexer hostname |

## Tests

### Vulnerability Retrieval

### Test: Get vulnerabilities with default parameters

1. Connect to the MCP server
2. Call `get_wazuh_vulnerabilities` tool with no arguments

**Expect:**
- List of vulnerabilities is returned
- Each vulnerability includes relevant information (CVE, severity, agent, etc.)
- Default limit of 100 vulnerabilities is applied
- Response format is readable JSON or text

---

### Test: Get vulnerabilities with custom limit

1. Call `get_wazuh_vulnerabilities` tool with limit set to 20

**Expect:**
- At most 20 vulnerabilities are returned
- Response contains no more than 20 vulnerability entries
- If fewer than 20 vulnerabilities exist, all available are returned

---

### Vulnerability Filtering

### Test: Filter vulnerabilities by agent ID

1. Identify a known agent ID that has vulnerabilities
2. Call `get_wazuh_vulnerabilities` tool with agent_id set to that ID

**Expect:**
- Only vulnerabilities for the specified agent are returned
- All returned vulnerabilities are associated with that agent
- Response is filtered correctly

---

### Test: Filter vulnerabilities by Critical severity

1. Call `get_wazuh_vulnerabilities` tool with severity set to "Critical"

**Expect:**
- Only Critical severity vulnerabilities are returned
- All returned vulnerabilities have Critical severity
- Response is filtered correctly

---

### Test: Filter vulnerabilities by High severity

1. Call `get_wazuh_vulnerabilities` tool with severity set to "High"

**Expect:**
- Only High severity vulnerabilities are returned
- All returned vulnerabilities have High severity
- Response is filtered correctly

---

### Test: Filter vulnerabilities by Medium severity

1. Call `get_wazuh_vulnerabilities` tool with severity set to "Medium"

**Expect:**
- Only Medium severity vulnerabilities are returned
- All returned vulnerabilities have Medium severity
- Response is filtered correctly

---

### Test: Filter vulnerabilities by Low severity

1. Call `get_wazuh_vulnerabilities` tool with severity set to "Low"

**Expect:**
- Only Low severity vulnerabilities are returned
- All returned vulnerabilities have Low severity
- Response is filtered correctly

---

### Test: Combine agent and severity filters

1. Identify a known agent ID
2. Call `get_wazuh_vulnerabilities` tool with both agent_id and severity set to "Critical"

**Expect:**
- Only Critical vulnerabilities for the specified agent are returned
- Filters are applied as AND conditions
- Response is correctly filtered

---

### Critical Vulnerabilities

### Test: Get critical vulnerabilities with default limit

1. Call `get_wazuh_critical_vulnerabilities` tool with no arguments

**Expect:**
- Only Critical severity vulnerabilities are returned
- Default limit of 50 is applied
- All returned vulnerabilities have Critical severity
- Response format is readable

---

### Test: Get critical vulnerabilities with custom limit

1. Call `get_wazuh_critical_vulnerabilities` tool with limit set to 10

**Expect:**
- At most 10 Critical vulnerabilities are returned
- All returned vulnerabilities have Critical severity
- Response contains no more than 10 entries

---

### Test: Get critical vulnerabilities when none exist

1. If possible, test with a system that has no Critical vulnerabilities
2. Call `get_wazuh_critical_vulnerabilities` tool

**Expect:**
- Tool returns appropriate message (e.g., empty list or "No critical vulnerabilities found")
- Response is not an error
- Message is user-friendly

---

### Vulnerability Summary

### Test: Get vulnerability summary with default time range

1. Call `get_wazuh_vulnerability_summary` tool with no arguments

**Expect:**
- Statistical summary of vulnerabilities is returned
- Summary includes counts by severity (if available)
- Default time range (7d) is used
- Response format is readable JSON or text

---

### Test: Get vulnerability summary for specific time range

1. Call `get_wazuh_vulnerability_summary` tool with time_range set to "30d"

**Expect:**
- Summary covers the last 30 days
- Statistics reflect vulnerabilities from the specified time range
- Response is returned successfully

---

### Test: Get vulnerability summary for 24 hours

1. Call `get_wazuh_vulnerability_summary` tool with time_range set to "24h"

**Expect:**
- Summary covers the last 24 hours
- Statistics reflect vulnerabilities from the last day
- Response format is readable

---

### Edge Cases

### Test: Handle empty vulnerability results gracefully

1. Call `get_wazuh_vulnerabilities` when no vulnerabilities exist (or use filters that match nothing)

**Expect:**
- Tool returns appropriate message (e.g., empty list or "No vulnerabilities found")
- Response is not an error
- Message is user-friendly

---

### Test: Handle invalid severity value

1. Call `get_wazuh_vulnerabilities` tool with severity set to "InvalidSeverity"

**Expect:**
- Tool either validates and rejects the input or handles it gracefully
- Error message is clear if validation fails
- Server does not crash

---

### Test: Handle invalid agent ID

1. Call `get_wazuh_vulnerabilities` tool with agent_id set to "99999" (non-existent)

**Expect:**
- Tool either returns empty results or an error
- Error message is clear if agent not found
- Server does not crash

---

### Test: Handle Wazuh API errors

1. Temporarily make Wazuh Manager or Indexer unreachable
2. Call `get_wazuh_vulnerabilities` tool

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running
- Tool works again when APIs are available

---

### Test: Handle malformed vulnerability data

1. If possible, simulate malformed vulnerability data in Wazuh
2. Call `get_wazuh_vulnerabilities` tool

**Expect:**
- Tool handles missing or malformed fields gracefully
- Default values are used for missing fields
- Server does not crash
- Response is still readable

---

### Test: Handle very large limit values

1. Call `get_wazuh_vulnerabilities` tool with limit set to 10000

**Expect:**
- Tool either uses a maximum allowed limit or returns an error
- Server does not crash
- Response is valid

---

### Test: Handle invalid time range format

1. Call `get_wazuh_vulnerability_summary` tool with time_range set to "invalid-format"

**Expect:**
- Tool either validates and rejects the input or uses a default
- Error message is clear if validation fails
- Server does not crash

---

## Teardown

1. Restore Wazuh Manager and Indexer connectivity if disrupted
2. Close MCP client connections
