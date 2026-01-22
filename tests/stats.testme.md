# TESTME: Statistics and Monitoring Tools

Tests for Wazuh statistics retrieval including manager statistics, weekly stats, remoted stats, and log collector stats.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Manager API is accessible
- Wazuh system has been running for at least some time (for meaningful statistics)

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_API_PORT | 55000 | Wazuh Manager port |

## Tests

### Manager Statistics

### Test: Get comprehensive Wazuh manager statistics

1. Connect to the MCP server
2. Call `get_wazuh_statistics` tool with no arguments

**Expect:**
- Comprehensive statistics are returned
- Statistics include performance and operational metrics
- Response format is readable JSON or text
- Statistics include relevant manager information

---

### Weekly Statistics

### Test: Get weekly security statistics

1. Call `get_wazuh_weekly_stats` tool with no arguments

**Expect:**
- Historical security statistics for the past week are returned
- Statistics are aggregated over the week
- Response format is readable JSON or text
- Statistics include relevant weekly metrics

---

### Test: Weekly stats reflect past 7 days

1. Call `get_wazuh_weekly_stats` tool
2. Verify the time range in the response (if included)

**Expect:**
- Statistics cover the past 7 days
- Time range is correctly calculated
- Response is returned successfully

---

### Remoted Statistics

### Test: Get remoted service statistics

1. Call `get_wazuh_remoted_stats` tool with no arguments

**Expect:**
- Remoted service statistics are returned
- Statistics include agent connection information
- Statistics include data throughput information
- Response format is readable JSON or text

---

### Test: Remoted stats show connection metrics

1. Call `get_wazuh_remoted_stats` tool
2. Inspect the response

**Expect:**
- Response includes connection-related metrics
- Response includes throughput-related metrics
- Statistics are relevant to the remoted service

---

### Log Collector Statistics

### Test: Get log collector service statistics

1. Call `get_wazuh_log_collector_stats` tool with no arguments

**Expect:**
- Log collector statistics are returned
- Statistics include log collection performance metrics
- Response format is readable JSON or text
- Statistics are relevant to the log collector service

---

### Edge Cases

### Test: Handle statistics when system is new

1. If possible, test with a newly installed Wazuh system
2. Call `get_wazuh_statistics` tool

**Expect:**
- Statistics are returned (may be minimal or zero values)
- Response is not an error
- Response format is valid

---

### Test: Handle Wazuh Manager API errors

1. Temporarily make Wazuh Manager API unreachable
2. Call any statistics tool (e.g., `get_wazuh_statistics`)

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running
- Tool works again when Manager is available

---

### Test: Handle missing statistics data

1. If possible, test with a Wazuh system that has incomplete statistics
2. Call `get_wazuh_statistics` tool

**Expect:**
- Tool handles missing data gracefully
- Default values or empty fields are used for missing data
- Server does not crash
- Response is still readable

---

## Teardown

1. Restore Wazuh Manager connectivity if disrupted
2. Close MCP client connections
