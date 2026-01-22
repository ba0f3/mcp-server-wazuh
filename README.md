# Wazuh MCP Server - Talk to your SIEM

A Go-based server (ported from Rust) designed to bridge the gap between a Wazuh Security Information and Event Management (SIEM) system and applications requiring contextual security data, specifically tailored for the Claude Desktop Integration using the Model Context Protocol (MCP).

> **Note:** This project is a fork of [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh), which was originally written in Rust. This Go port maintains feature parity with the original while providing improved maintainability and cross-platform compatibility.

## Overview

Modern AI assistants like Claude can benefit significantly from real-time context about the user's security environment. The Wazuh MCP Server bridges this gap by providing comprehensive access to Wazuh SIEM data through natural language interactions.

This server transforms complex Wazuh API responses into MCP-compatible format, enabling AI assistants to access:

- **Security Alerts & Events** from the Wazuh Indexer for threat detection and incident response
- **Agent Management & Monitoring** including health status, system processes, and network ports
- **Vulnerability Assessment** data for risk management and patch prioritization  
- **Security Rules & Configuration** for detection optimization and compliance validation
- **System Statistics & Performance** metrics for operational monitoring and audit trails
- **Log Analysis & Forensics** capabilities for incident investigation and compliance reporting
- **Cluster Health & Management** for infrastructure reliability and availability requirements
- **Compliance Monitoring & Gap Analysis** for regulatory frameworks like PCI-DSS, HIPAA, SOX, and GDPR

Rather than requiring manual API calls or complex queries, security teams can now ask natural language questions like "Show me critical vulnerabilities on web servers," "What processes are running on agent 001?" or "Are we meeting PCI-DSS logging requirements?" and receive structured, actionable data from their Wazuh deployment.

The server implements **42 specialized security tools** to provide comprehensive SIEM interaction capabilities, including experimental APIs for advanced security operations.

![](media/wazuh-alerts-1.png)

## Available Tools

The Wazuh MCP Server provides 42 specialized security tools categorized as follows:

### Alert Management (5 tools)
- `get_wazuh_alerts`: Retrieve security alerts with optional filtering by rule ID, level, agent, or timestamp.
- `get_wazuh_alert_summary`: Retrieve a summary of security alerts grouped by specific fields.
- `analyze_alert_patterns`: Identify recurring attack patterns or trends in security alerts.
- `search_security_events`: Perform advanced search across security events and logs.
- `get_top_security_threats`: Identify the top security threats currently active in the environment.

### Agent Management (9 tools)
- `get_wazuh_agents`: List all agents with status, IP, and OS details.
- `get_wazuh_running_agents`: Quickly retrieve all currently active/running agents.
- `get_agent_processes`: List running processes on a specific agent (Syscollector).
- `get_agent_ports`: List open network ports on a specific agent (Syscollector).
- `get_agent_configuration`: Retrieve active configuration of a specific agent (requires component and configuration parameters).
- `get_agent_summary_os`: Retrieve a summary of agents grouped by operating system.
- `get_agent_summary_status`: Retrieve a summary of agents grouped by status.
- `get_agent_groups`: Retrieve a list of all agent groups.
- `get_agent_distinct_stats`: Retrieve distinct statistics for a specific agent field.

### Vulnerability Management
- `get_wazuh_vulnerabilities`: List detected vulnerabilities with filtering by agent or severity.
- `get_wazuh_critical_vulnerabilities`: Identify critical severity vulnerabilities requiring immediate action.
- `get_wazuh_vulnerability_summary`: Get statistical summary of vulnerabilities across the environment.


### System Statistics & Logs (7 tools)
- `get_wazuh_manager_daemon_stats`: Retrieve comprehensive daemon statistics of the Wazuh manager (replaces deprecated endpoint).
- `get_wazuh_weekly_stats`: Retrieve historical security statistics for the past week.
- `get_agent_daemon_stats`: Retrieve daemon statistics for a specific agent.
- `get_agent_log_collector_stats`: Retrieve log collector statistics for a specific agent.
- `search_wazuh_manager_logs`: Search internal manager logs for troubleshooting.
- `get_wazuh_manager_error_logs`: Specifically retrieve error-level logs from the manager.
- `validate_wazuh_connection`: Verify authentication and connectivity to Wazuh API.

### Rules & Cluster (3 tools)
- `get_wazuh_rules_summary`: Statistical summary of all active security rules.
- `get_wazuh_cluster_health`: Health status and synchronization state of the Wazuh cluster.
- `get_wazuh_cluster_nodes`: List all nodes in the Wazuh cluster with their status.

### Experimental APIs

#### SCA (Security Configuration Assessment) (3 tools)
- `get_sca_policies`: Retrieve SCA policies for an agent.
- `get_sca_policy_checks`: Retrieve checks for a specific SCA policy on an agent.
- `get_sca_summary`: Retrieve a summary of SCA results for an agent.

#### Decoders (3 tools)
- `get_decoders`: Retrieve all Wazuh decoders (log parsing rules).
- `get_decoder_files`: Retrieve list of decoder files.
- `get_decoders_by_file`: Retrieve decoders from a specific file.

#### Rootcheck (2 tools)
- `get_rootcheck_database`: Retrieve rootcheck database results for an agent (rootkit detection).
- `get_rootcheck_last_scan`: Retrieve the last rootcheck scan time for an agent.

#### MITRE ATT&CK (3 tools)
- `get_mitre_techniques`: Retrieve MITRE ATT&CK techniques.
- `get_mitre_technique_by_id`: Retrieve a specific MITRE ATT&CK technique by ID.
- `get_mitre_agents`: Retrieve agents with MITRE ATT&CK techniques.

#### Active Response (2 tools)
- `execute_active_response`: Execute active response commands on an agent or all agents.
- `get_active_response_logs`: Retrieve active response execution logs.

#### CDB Lists (2 tools)
- `get_cdb_lists`: Retrieve all CDB (Custom Database) lists.
- `get_cdb_list_file`: Retrieve entries from a specific CDB list file.

## Requirements

-   An MCP (Model Context Protocol) compatible LLM client (e.g., Claude Desktop)
-   A running Wazuh server (v4.12 recommended) with the API enabled and accessible.
-   Network connectivity between this server and the Wazuh API.

## Installation

### Option 1: Download Pre-built Binary (Recommended)

1.  **Download the Binary:**
    *   Go to the [Releases page](https://github.com/ba0f3/mcp-server-wazuh/releases) of the `mcp-server-wazuh` GitHub repository.
    *   Download the appropriate binary for your operating system.
    *   Make the downloaded binary executable (e.g., `chmod +x mcp-server-wazuh-linux-amd64`).

### Option 2: Docker 

1.  **Pull the Docker Image:**
    ```bash
    docker pull ghcr.io/ba0f3/mcp-server-wazuh:latest
    ```

### Option 3: Build from Source

1.  **Prerequisites:**
    *   Install Go 1.25 or later: [https://go.dev/doc/install](https://go.dev/doc/install)

2.  **Build:**
    ```bash
    git clone https://github.com/ba0f3/mcp-server-wazuh.git
    cd mcp-server-wazuh
    go build -o mcp-server-wazuh ./cmd/mcp-server-wazuh
    ```

## Configuration

Configuration is managed through environment variables.

| Variable                 | Description                                                                    | Default     | Required |
| ------------------------ | ------------------------------------------------------------------------------ | ----------- | -------- |
| `WAZUH_API_HOST`         | Hostname or IP address of the Wazuh Manager API server.                        | `localhost` | Yes      |
| `WAZUH_API_PORT`         | Port number for the Wazuh Manager API.                                         | `55000`     | Yes      |
| `WAZUH_API_USERNAME`     | Username for Wazuh Manager API authentication.                                 | `wazuh`     | Yes      |
| `WAZUH_API_PASSWORD`     | Password for Wazuh Manager API authentication.                                 | `wazuh`     | Yes      |
| `WAZUH_INDEXER_HOST`     | Hostname or IP address of the Wazuh Indexer API server.                        | `localhost` | Yes      |
| `WAZUH_INDEXER_PORT`     | Port number for the Wazuh Indexer API.                                         | `9200`      | Yes      |
| `WAZUH_INDEXER_USERNAME` | Username for Wazuh Indexer API authentication.                                 | `admin`     | Yes      |
| `WAZUH_INDEXER_PASSWORD` | Password for Wazuh Indexer API authentication.                                 | `admin`     | Yes      |
| `WAZUH_VERIFY_SSL`       | Set to `true` to verify SSL certificates for Wazuh API connections.            | `false`     | No       |
| `MCP_SERVER_TRANSPORT`    | Transport mode: `stdio` (default) or `http`.                                  | `stdio`     | No       |

## Development & Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...
```

## License

This project is licensed under the [MIT License](LICENSE).
