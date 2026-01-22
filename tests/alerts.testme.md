# TESTME: Alert Management Tools

Tests for Wazuh alert retrieval, filtering, analysis, and search capabilities.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Indexer is accessible and contains alert data
- At least some security alerts exist in the Wazuh system (for positive test cases)

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_INDEXER_HOST | localhost | Wazuh Indexer hostname |
| WAZUH_INDEXER_PORT | 9200 | Wazuh Indexer port |
| WAZUH_INDEXER_USERNAME | admin | Indexer username |
| WAZUH_INDEXER_PASSWORD | admin | Indexer password |

## Tests

### Alert Retrieval

### Test: Get alerts with default parameters

1. Connect to the MCP server
2. Call `get_wazuh_alerts` tool with no arguments

**Expect:**
- Tool returns a list of alerts (or "No Wazuh alerts found" if empty)
- Each alert includes: Alert ID, Time, Agent, Level, Description
- Default limit of 100 alerts is applied
- Response format is readable text

---

### Test: Get alerts with custom limit

1. Connect to the MCP server
2. Call `get_wazuh_alerts` with limit set to 10

**Expect:**
- Tool returns at most 10 alerts
- Response contains no more than 10 alert entries
- If fewer than 10 alerts exist, all available alerts are returned

---

### Test: Get alerts respects maximum limit

1. Connect to the MCP server
2. Call `get_wazuh_alerts` with limit set to 2000 (exceeds maximum)

**Expect:**
- Tool either uses the maximum allowed limit (1000) or returns an error
- Server does not crash
- Response is valid

---

### Alert Filtering

### Test: Filter alerts by rule ID

1. Identify a known rule ID from existing alerts
2. Call `get_wazuh_alerts` with rule_id parameter set to that rule ID

**Expect:**
- Only alerts matching the specified rule ID are returned
- All returned alerts have the same rule ID
- Response is not empty if matching alerts exist

---

### Test: Filter alerts by level

1. Call `get_wazuh_alerts` with level parameter set to "12"

**Expect:**
- Only alerts with level 12 are returned
- All returned alerts have level 12
- Response format includes level information

---

### Test: Filter alerts by level range

1. Call `get_wazuh_alerts` with level parameter set to "10+"

**Expect:**
- Only alerts with level 10 or higher are returned
- All returned alerts have level >= 10
- Response is filtered correctly

---

### Test: Filter alerts by agent ID

1. Identify a known agent ID from existing alerts
2. Call `get_wazuh_alerts` with agent_id parameter set to that agent ID

**Expect:**
- Only alerts from the specified agent are returned
- All returned alerts show the same agent name/ID
- Response is filtered correctly

---

### Test: Filter alerts by timestamp range

1. Determine a time range (e.g., last 24 hours)
2. Call `get_wazuh_alerts` with timestamp_start and timestamp_end parameters in ISO format

**Expect:**
- Only alerts within the specified time range are returned
- All returned alerts have timestamps within the range
- ISO timestamp format is accepted correctly

---

### Test: Combine multiple filters

1. Call `get_wazuh_alerts` with multiple filters: rule_id, level, and agent_id

**Expect:**
- Only alerts matching all specified filters are returned
- Filters are applied as AND conditions
- Response is correctly filtered

---

### Alert Summary

### Test: Get alert summary with default grouping

1. Call `get_wazuh_alert_summary` tool with no arguments

**Expect:**
- Summary is returned grouped by rule.level (default)
- Summary shows statistical information
- Response format is readable JSON or text

---

### Test: Get alert summary for specific time range

1. Call `get_wazuh_alert_summary` with time_range set to "24h"

**Expect:**
- Summary covers the last 24 hours
- Statistics reflect alerts from the specified time range
- Response is returned successfully

---

### Test: Get alert summary grouped by custom field

1. Call `get_wazuh_alert_summary` with group_by set to "agent.name"

**Expect:**
- Summary is grouped by agent name
- Statistics are organized by agent
- Response format reflects the grouping

---

### Alert Pattern Analysis

### Test: Analyze alert patterns

1. Call `analyze_alert_patterns` tool

**Expect:**
- Pattern analysis is performed
- Recurring patterns or trends are identified
- Response includes analysis results

---

### Test: Analyze alert patterns for specific time range

1. Call `analyze_alert_patterns` with time_range parameter set to "7d"

**Expect:**
- Analysis covers the last 7 days
- Patterns reflect the specified time range
- Response is returned successfully

---

### Security Event Search

### Test: Search security events with query

1. Call `search_security_events` tool with a search query

**Expect:**
- Search is performed across security events
- Matching events are returned
- Response format is readable

---

### Test: Search security events with filters

1. Call `search_security_events` with query and additional filters (e.g., agent_id, time_range)

**Expect:**
- Search respects all specified filters
- Results match the query and filters
- Response is correctly filtered

---

### Edge Cases

### Test: Handle empty alert results gracefully

1. Call `get_wazuh_alerts` when no alerts exist (or use filters that match nothing)

**Expect:**
- Tool returns "No Wazuh alerts found." message
- Response is not an error
- Message is user-friendly

---

### Test: Handle invalid timestamp format

1. Call `get_wazuh_alerts` with timestamp_start in invalid format (e.g., "invalid-date")

**Expect:**
- Tool either validates and rejects the input or handles it gracefully
- Error message is clear if validation fails
- Server does not crash

---

### Test: Handle malformed alert data

1. If possible, simulate malformed alert data in Wazuh Indexer
2. Call `get_wazuh_alerts` tool

**Expect:**
- Tool handles missing or malformed fields gracefully
- Default values are used for missing fields (e.g., "Unknown ID", "Unknown agent")
- Server does not crash
- Response is still readable

---

### Test: Handle Wazuh Indexer connection errors

1. Temporarily make Wazuh Indexer unreachable
2. Call `get_wazuh_alerts` tool

**Expect:**
- Tool returns an error response
- Error message indicates connection failure
- Server remains running
- Tool works again when Indexer is available

---

## Teardown

1. Restore Wazuh Indexer connectivity if it was disrupted
2. Close MCP client connections
