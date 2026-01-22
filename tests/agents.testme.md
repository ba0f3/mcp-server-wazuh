# TESTME: Agent Management Tools

Tests for Wazuh agent listing, health checks, process monitoring, port monitoring, and configuration retrieval.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Manager API is accessible
- At least one Wazuh agent is registered in the system

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_API_PORT | 55000 | Wazuh Manager port |
| WAZUH_API_USERNAME | wazuh | Manager username |
| WAZUH_API_PASSWORD | wazuh | Manager password |

## Tests

### Agent Listing

### Test: Get all agents with default parameters

1. Connect to the MCP server
2. Call `get_wazuh_agents` tool with no arguments

**Expect:**
- List of all agents is returned
- Each agent shows: status indicator (🟢/🟡/🔴), Agent ID, Name, IP (if available), OS info, Version
- Default limit of 100 agents is applied
- Response format is readable

---

### Test: Get agents with custom limit

1. Call `get_wazuh_agents` with limit set to 5

**Expect:**
- At most 5 agents are returned
- Response contains no more than 5 agent entries
- If fewer than 5 agents exist, all available agents are returned

---

### Test: Filter agents by status

1. Call `get_wazuh_agents` with status set to "active"

**Expect:**
- Only active agents are returned
- All returned agents have status "active"
- Status indicator shows 🟢 for all agents

---

### Test: Filter agents by disconnected status

1. Call `get_wazuh_agents` with status set to "disconnected"

**Expect:**
- Only disconnected agents are returned
- All returned agents have status "disconnected"
- Status indicator shows 🔴 for disconnected agents

---

### Test: Filter agents by name

1. Identify a known agent name
2. Call `get_wazuh_agents` with name parameter set to that agent name

**Expect:**
- Only agents matching the specified name are returned
- All returned agents have the matching name
- Response is filtered correctly

---

### Test: Filter agents by IP address

1. Identify a known agent IP address
2. Call `get_wazuh_agents` with ip parameter set to that IP

**Expect:**
- Only agents with the specified IP are returned
- All returned agents show the matching IP
- Response is filtered correctly

---

### Test: Filter agents by group

1. Identify a known agent group
2. Call `get_wazuh_agents` with group parameter set to that group name

**Expect:**
- Only agents in the specified group are returned
- Response is filtered correctly

---

### Test: Filter agents by OS platform

1. Call `get_wazuh_agents` with os_platform parameter (e.g., "linux", "windows")

**Expect:**
- Only agents with the specified OS platform are returned
- All returned agents show matching OS information
- Response is filtered correctly

---

### Test: Filter agents by version

1. Call `get_wazuh_agents` with version parameter set to a specific version

**Expect:**
- Only agents with the specified version are returned
- All returned agents show the matching version
- Response is filtered correctly

---

### Test: Get specific agent by ID

1. Identify a known agent ID
2. Call `get_wazuh_agents` with agent_id parameter set to that ID

**Expect:**
- Only the specified agent is returned
- Response contains exactly one agent
- Agent details match the specified ID

---

### Test: Get running agents only

1. Call `get_wazuh_running_agents` tool

**Expect:**
- Only active/running agents are returned
- All returned agents have active status
- Response format is readable

---

### Agent Health

### Test: Check agent health for valid agent

1. Identify a known active agent ID
2. Call `check_agent_health` tool with agent_id set to that ID

**Expect:**
- Health status is returned
- Response includes connection status
- Response includes synchronization status
- Health information is readable

---

### Test: Check agent health for invalid agent ID

1. Call `check_agent_health` with agent_id set to "99999" (non-existent)

**Expect:**
- Tool returns an error response
- Error message indicates agent not found
- Server does not crash

---

### Agent Processes

### Test: Get processes for valid agent

1. Identify a known agent ID with Syscollector enabled
2. Call `get_agent_processes` tool with agent_id set to that ID

**Expect:**
- List of running processes is returned
- Each process shows relevant information (PID, name, etc.)
- Response format is readable
- Response is not empty (if agent has processes)

---

### Test: Get processes for agent without Syscollector

1. Identify an agent ID that doesn't have Syscollector data
2. Call `get_agent_processes` tool with that agent_id

**Expect:**
- Tool either returns empty results or an appropriate message
- Error message is clear if Syscollector data is unavailable
- Server does not crash

---

### Agent Ports

### Test: Get network ports for valid agent

1. Identify a known agent ID with Syscollector enabled
2. Call `get_agent_ports` tool with agent_id set to that ID

**Expect:**
- List of open network ports is returned
- Each port shows relevant information (port number, protocol, process, etc.)
- Response format is readable
- Response is not empty (if agent has open ports)

---

### Test: Get ports for agent without Syscollector

1. Identify an agent ID that doesn't have Syscollector data
2. Call `get_agent_ports` tool with that agent_id

**Expect:**
- Tool either returns empty results or an appropriate message
- Error message is clear if Syscollector data is unavailable
- Server does not crash

---

### Agent Configuration

### Test: Get agent configuration for valid agent

1. Identify a known agent ID
2. Call `get_agent_configuration` tool with agent_id set to that ID

**Expect:**
- Agent configuration is returned
- Configuration includes active settings
- Response format is readable (JSON or text)

---

### Test: Get configuration for invalid agent ID

1. Call `get_agent_configuration` with agent_id set to "99999" (non-existent)

**Expect:**
- Tool returns an error response
- Error message indicates agent not found
- Server does not crash

---

### Edge Cases

### Test: Handle empty agent list gracefully

1. If possible, test with a Wazuh instance that has no agents
2. Call `get_wazuh_agents` tool

**Expect:**
- Tool returns "No agents found." message
- Response is not an error
- Message is user-friendly

---

### Test: Handle agent with missing fields

1. If possible, test with an agent that has incomplete data
2. Call `get_wazuh_agents` tool

**Expect:**
- Tool handles missing fields gracefully
- Default values are used for missing information
- Response is still readable
- Server does not crash

---

### Test: Handle Wazuh Manager API errors

1. Temporarily make Wazuh Manager API unreachable
2. Call `get_wazuh_agents` tool

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running
- Tool works again when Manager is available

---

### Test: Handle invalid filter combinations

1. Call `get_wazuh_agents` with conflicting filters (if applicable)

**Expect:**
- Tool either applies filters correctly or returns an error
- Error message is clear if filters are invalid
- Server does not crash

---

## Teardown

1. Restore Wazuh Manager connectivity if it was disrupted
2. Close MCP client connections
