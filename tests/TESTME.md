# TESTME: Test Suite Index

This directory contains feature-specific test specifications for the Wazuh MCP Server.

## Test Files

| File | Description | Tool Count |
|------|-------------|------------|
| [alerts.testme.md](./alerts.testme.md) | Alert management and search tools | 4 tools |
| [agents.testme.md](./agents.testme.md) | Agent management and monitoring tools | 6 tools |
| [security.testme.md](./security.testme.md) | Security analysis and compliance tools | 6 tools |
| [vulnerabilities.testme.md](./vulnerabilities.testme.md) | Vulnerability management tools | 3 tools |
| [stats.testme.md](./stats.testme.md) | Statistics and monitoring tools | 4 tools |
| [logs.testme.md](./logs.testme.md) | Log management and validation tools | 3 tools |
| [rules.testme.md](./rules.testme.md) | Security rules tools | 1 tool |
| [cluster.testme.md](./cluster.testme.md) | Cluster management tools | 2 tools |

## Test Coverage

These test files cover all **29 specialized security tools** provided by the Wazuh MCP Server:

### Alert Management (4 tools)
- `get_wazuh_alerts` - Retrieve security alerts with filtering
- `get_wazuh_alert_summary` - Get summary of alerts grouped by fields
- `analyze_alert_patterns` - Identify recurring attack patterns
- `search_security_events` - Advanced search across security events

### Agent Management (6 tools)
- `get_wazuh_agents` - List all agents with status and details
- `get_wazuh_running_agents` - Get currently active agents
- `check_agent_health` - Verify agent health and connection
- `get_agent_processes` - List running processes on an agent
- `get_agent_ports` - List open network ports on an agent
- `get_agent_configuration` - Retrieve agent configuration

### Vulnerability Management (3 tools)
- `get_wazuh_vulnerabilities` - List detected vulnerabilities
- `get_wazuh_critical_vulnerabilities` - Get critical severity vulnerabilities
- `get_wazuh_vulnerability_summary` - Get statistical summary of vulnerabilities

### Security Analysis (6 tools)
- `analyze_security_threat` - Analyze threat indicators
- `check_ioc_reputation` - Check IOC global reputation
- `perform_risk_assessment` - Execute risk assessments
- `get_top_security_threats` - Identify top active threats
- `generate_security_report` - Generate security reports
- `run_compliance_check` - Execute compliance audits

### Statistics (4 tools)
- `get_wazuh_statistics` - Get comprehensive manager statistics
- `get_wazuh_weekly_stats` - Get historical weekly statistics
- `get_wazuh_remoted_stats` - Get remoted service statistics
- `get_wazuh_log_collector_stats` - Get log collector statistics

### Logs (3 tools)
- `search_wazuh_manager_logs` - Search manager internal logs
- `get_wazuh_manager_error_logs` - Get error-level logs
- `validate_wazuh_connection` - Verify connection and authentication

### Rules (1 tool)
- `get_wazuh_rules_summary` - Get statistical summary of security rules

### Cluster (2 tools)
- `get_wazuh_cluster_health` - Get cluster health and sync status
- `get_wazuh_cluster_nodes` - List all cluster nodes with status

## Running Tests

Each test file can be executed independently. Tests are designed to be:

- **Framework-agnostic** - No dependencies on specific testing libraries
- **Human-readable** - Clear steps that anyone can follow
- **Agent-executable** - AI agents can execute these tests automatically
- **Independent** - Tests don't depend on each other (unless explicitly noted)

## Prerequisites

Before running any test file, ensure:

1. Wazuh MCP Server is built and running
2. Required environment variables are set (see individual test files)
3. Wazuh Manager and Indexer APIs are accessible
4. Appropriate test data exists in Wazuh (for positive test cases)

## Common Environment Variables

All test files may use these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_API_PORT | 55000 | Wazuh Manager port |
| WAZUH_API_USERNAME | wazuh | Manager username |
| WAZUH_API_PASSWORD | wazuh | Manager password |
| WAZUH_INDEXER_HOST | localhost | Wazuh Indexer hostname |
| WAZUH_INDEXER_PORT | 9200 | Wazuh Indexer port |
| WAZUH_INDEXER_USERNAME | admin | Indexer username |
| WAZUH_INDEXER_PASSWORD | admin | Indexer password |

See the main [TESTME.md](../TESTME.md) in the repository root for server-level integration tests.
