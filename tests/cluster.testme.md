# TESTME: Cluster Management Tools

Tests for Wazuh cluster health monitoring and node listing.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Manager API is accessible
- Wazuh cluster is configured (for positive test cases)
- Note: Some tests may not apply to single-node deployments

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_API_PORT | 55000 | Wazuh Manager port |

## Tests

### Cluster Health

### Test: Get cluster health status

1. Connect to the MCP server
2. Call `get_wazuh_cluster_health` tool with no arguments

**Expect:**
- Cluster health status is returned
- Response includes synchronization state
- Response includes health information
- Response format is readable JSON or text

---

### Test: Cluster health shows synchronization status

1. Call `get_wazuh_cluster_health` tool
2. Inspect the response

**Expect:**
- Response includes synchronization state information
- Health status is clearly indicated
- Response format is readable

---

### Test: Cluster health for single-node deployment

1. If testing with a single-node Wazuh deployment
2. Call `get_wazuh_cluster_health` tool

**Expect:**
- Tool either returns appropriate response for single-node or indicates cluster is not configured
- Response is not an error
- Response format is valid

---

### Cluster Nodes

### Test: Get cluster nodes list

1. Call `get_wazuh_cluster_nodes` tool with no arguments

**Expect:**
- List of cluster nodes is returned
- Each node includes status information
- Response format is readable JSON or text
- Response includes all nodes in the cluster

---

### Test: Cluster nodes show status for each node

1. Call `get_wazuh_cluster_nodes` tool
2. Inspect the response

**Expect:**
- Each node in the response includes status
- Node statuses are clearly indicated
- Response format is readable

---

### Test: Cluster nodes for single-node deployment

1. If testing with a single-node Wazuh deployment
2. Call `get_wazuh_cluster_nodes` tool

**Expect:**
- Tool either returns the single node or indicates cluster is not configured
- Response is not an error
- Response format is valid

---

### Edge Cases

### Test: Handle cluster tools when cluster is not configured

1. If possible, test with a Wazuh system that doesn't have cluster configured
2. Call `get_wazuh_cluster_health` tool

**Expect:**
- Tool either returns appropriate response or indicates cluster is not available
- Response is not an error (may indicate cluster not configured)
- Server does not crash

---

### Test: Handle Wazuh Manager API errors

1. Temporarily make Wazuh Manager API unreachable
2. Call `get_wazuh_cluster_health` tool

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running
- Tool works again when Manager is available

---

### Test: Handle malformed cluster data

1. If possible, simulate malformed cluster data in Wazuh
2. Call `get_wazuh_cluster_nodes` tool

**Expect:**
- Tool handles malformed data gracefully
- Server does not crash
- Response is still readable (may show partial data)

---

## Teardown

1. Restore Wazuh Manager connectivity if disrupted
2. Close MCP client connections
