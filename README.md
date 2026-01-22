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

The server implements **29 specialized security tools** to provide comprehensive SIEM interaction capabilities.

![](media/wazuh-alerts-1.png)

## Available Tools

The Wazuh MCP Server provides 29 specialized security tools categorized as follows:

### Alert Management
- `get_wazuh_alerts`: Retrieve security alerts with optional filtering by rule ID, level, agent, or timestamp.
- `get_wazuh_alert_summary`: Retrieve a summary of security alerts grouped by specific fields.
- `analyze_alert_patterns`: Identify recurring attack patterns or trends in security alerts.
- `search_security_events`: Perform advanced search across security events and logs.

### Agent Management
- `get_wazuh_agents`: List all agents with status, IP, and OS details.
- `get_wazuh_running_agents`: Quickly retrieve all currently active/running agents.
- `check_agent_health`: Verify health status, connection, and synchronization of a specific agent.
- `get_agent_processes`: List running processes on a specific agent (Syscollector).
- `get_agent_ports`: List open network ports on a specific agent (Syscollector).
- `get_agent_configuration`: Retrieve active configuration of a specific agent.

### Vulnerability Management
- `get_wazuh_vulnerabilities`: List detected vulnerabilities with filtering by agent or severity.
- `get_wazuh_critical_vulnerabilities`: Identify critical severity vulnerabilities requiring immediate action.
- `get_wazuh_vulnerability_summary`: Get statistical summary of vulnerabilities across the environment.

### Security Analysis & Compliance
- `analyze_security_threat`: Analyze threat indicators (IP, hash, domain) for risk and origin.
- `check_ioc_reputation`: Check global reputation of an Indicator of Compromise (IoC).
- `perform_risk_assessment`: Execute environment-wide or agent-specific risk assessments.
- `get_top_security_threats`: Identify the most active security threats.
- `generate_security_report`: Generate detailed executive, technical, or compliance reports.
- `run_compliance_check`: Execute audits against frameworks (PCI-DSS, GDPR, HIPAA, NIST).

### System Statistics & Logs
- `get_wazuh_statistics`: Retrieve comprehensive operational statistics of the Wazuh manager.
- `get_wazuh_weekly_stats`: Retrieve historical security statistics for the past week.
- `get_wazuh_remoted_stats`: Monitor agent connection and data throughput statistics.
- `get_wazuh_log_collector_stats`: Monitor log collection service performance.
- `search_wazuh_manager_logs`: Search internal manager logs for troubleshooting.
- `get_wazuh_manager_error_logs`: Specifically retrieve error-level logs from the manager.
- `validate_wazuh_connection`: Verify authentication and connectivity to Wazuh API.

### Rules & Cluster
- `get_wazuh_rules_summary`: Statistical summary of all active security rules.
- `get_wazuh_cluster_health`: Health status and synchronization state of the Wazuh cluster.
- `get_wazuh_cluster_nodes`: List all nodes in the Wazuh cluster with their status.

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
