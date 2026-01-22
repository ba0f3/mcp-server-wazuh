# TESTME: Security Analysis Tools

Tests for threat analysis, IOC reputation checking, risk assessment, top threats identification, security reporting, and compliance checking.

## Prerequisites

- Wazuh MCP Server is running and connected
- Wazuh Manager API is accessible
- Wazuh Indexer is accessible
- Security data exists in the Wazuh system

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| WAZUH_API_HOST | localhost | Wazuh Manager hostname |
| WAZUH_API_PORT | 55000 | Wazuh Manager port |
| WAZUH_INDEXER_HOST | localhost | Wazuh Indexer hostname |
| WAZUH_INDEXER_PORT | 9200 | Wazuh Indexer port |

## Tests

### Threat Analysis

### Test: Analyze security threat by IP address

1. Connect to the MCP server
2. Call `analyze_security_threat` tool with:
   - indicator: "192.168.1.100" (or a known IP from alerts)
   - indicator_type: "ip"

**Expect:**
- Threat analysis is performed
- Response includes risk assessment
- Response includes origin information (if available)
- Response format is readable JSON or text

---

### Test: Analyze security threat by hash

1. Call `analyze_security_threat` tool with:
   - indicator: "a1b2c3d4e5f6..." (a known file hash from alerts)
   - indicator_type: "hash"

**Expect:**
- Threat analysis is performed for the hash
- Response includes risk information
- Response format is readable

---

### Test: Analyze security threat by domain

1. Call `analyze_security_threat` tool with:
   - indicator: "example.com" (or a known domain from alerts)
   - indicator_type: "domain"

**Expect:**
- Threat analysis is performed for the domain
- Response includes risk assessment
- Response format is readable

---

### Test: Analyze threat with invalid indicator type

1. Call `analyze_security_threat` tool with:
   - indicator: "test-value"
   - indicator_type: "invalid_type"

**Expect:**
- Tool either handles the invalid type gracefully or returns an error
- Error message is clear if validation fails
- Server does not crash

---

### IOC Reputation

### Test: Check IOC reputation for IP address

1. Call `check_ioc_reputation` tool with:
   - indicator: "192.168.1.100"
   - indicator_type: "ip"

**Expect:**
- IOC reputation check is performed
- Response includes global reputation information
- Response format is readable JSON or text

---

### Test: Check IOC reputation for hash

1. Call `check_ioc_reputation` tool with:
   - indicator: "a1b2c3d4e5f6..."
   - indicator_type: "hash"

**Expect:**
- IOC reputation check is performed
- Response includes reputation data
- Response format is readable

---

### Test: Check IOC reputation for domain

1. Call `check_ioc_reputation` tool with:
   - indicator: "example.com"
   - indicator_type: "domain"

**Expect:**
- IOC reputation check is performed
- Response includes reputation information
- Response format is readable

---

### Risk Assessment

### Test: Perform environment-wide risk assessment

1. Call `perform_risk_assessment` tool with no arguments

**Expect:**
- Comprehensive risk assessment is performed
- Response includes risk scores or ratings
- Response covers the entire environment
- Response format is readable JSON or text

---

### Test: Perform agent-specific risk assessment

1. Identify a known agent ID
2. Call `perform_risk_assessment` tool with agent_id set to that ID

**Expect:**
- Risk assessment is performed for the specific agent
- Response includes agent-specific risk information
- Response format is readable

---

### Test: Perform risk assessment for invalid agent ID

1. Call `perform_risk_assessment` with agent_id set to "99999" (non-existent)

**Expect:**
- Tool either returns an error or handles it gracefully
- Error message is clear if agent not found
- Server does not crash

---

### Top Security Threats

### Test: Get top security threats with default parameters

1. Call `get_top_security_threats` tool with no arguments

**Expect:**
- Top 10 security threats are returned (default limit)
- Threats are ranked by activity or severity
- Response includes threat details
- Response format is readable

---

### Test: Get top security threats with custom limit

1. Call `get_top_security_threats` tool with limit set to 5

**Expect:**
- Top 5 security threats are returned
- Response contains exactly 5 threats (or fewer if less exist)
- Threats are properly ranked

---

### Test: Get top security threats for specific time range

1. Call `get_top_security_threats` tool with time_range set to "7d"

**Expect:**
- Top threats from the last 7 days are returned
- Response reflects threats in the specified time range
- Response format is readable

---

### Security Reporting

### Test: Generate executive security report

1. Call `generate_security_report` tool with report_type set to "executive"

**Expect:**
- Executive-level security report is generated
- Report includes high-level summary
- Report format is readable
- Report contains relevant metrics

---

### Test: Generate technical security report

1. Call `generate_security_report` tool with report_type set to "technical"

**Expect:**
- Technical security report is generated
- Report includes detailed technical information
- Report format is readable
- Report contains actionable data

---

### Test: Generate compliance security report

1. Call `generate_security_report` tool with report_type set to "compliance"

**Expect:**
- Compliance-focused security report is generated
- Report includes compliance-related information
- Report format is readable
- Report contains compliance metrics

---

### Test: Generate report for specific time range

1. Call `generate_security_report` tool with time_range set to "30d"

**Expect:**
- Report covers the last 30 days
- Report data reflects the specified time range
- Response is returned successfully

---

### Compliance Checking

### Test: Run PCI-DSS compliance check

1. Call `run_compliance_check` tool with framework set to "PCI-DSS"

**Expect:**
- PCI-DSS compliance audit is executed
- Response includes compliance status
- Response includes gap analysis
- Response format is readable

---

### Test: Run GDPR compliance check

1. Call `run_compliance_check` tool with framework set to "GDPR"

**Expect:**
- GDPR compliance audit is executed
- Response includes compliance status
- Response includes gap analysis
- Response format is readable

---

### Test: Run HIPAA compliance check

1. Call `run_compliance_check` tool with framework set to "HIPAA"

**Expect:**
- HIPAA compliance audit is executed
- Response includes compliance status
- Response includes gap analysis
- Response format is readable

---

### Test: Run NIST compliance check

1. Call `run_compliance_check` tool with framework set to "NIST"

**Expect:**
- NIST compliance audit is executed
- Response includes compliance status
- Response includes gap analysis
- Response format is readable

---

### Test: Run compliance check for invalid framework

1. Call `run_compliance_check` tool with framework set to "INVALID"

**Expect:**
- Tool either handles the invalid framework gracefully or returns an error
- Error message is clear if validation fails
- Server does not crash

---

### Edge Cases

### Test: Handle empty threat analysis results

1. Call `analyze_security_threat` with an indicator that has no matches

**Expect:**
- Tool returns appropriate response (may indicate no threats found)
- Response is not an error
- Message is user-friendly

---

### Test: Handle API errors gracefully

1. Temporarily make Wazuh Manager or Indexer unreachable
2. Call any security analysis tool

**Expect:**
- Tool returns an error response
- Error message indicates connection or API failure
- Server remains running
- Tool works again when APIs are available

---

### Test: Handle missing required parameters

1. Call `analyze_security_threat` without indicator parameter

**Expect:**
- Tool either uses defaults or returns an error
- Error message is clear if parameter is required
- Server does not crash

---

### Test: Handle large time ranges

1. Call `get_top_security_threats` with time_range set to "365d" (1 year)

**Expect:**
- Tool handles the large time range
- Response is returned (may take longer)
- Response format is valid

---

## Teardown

1. Restore Wazuh Manager and Indexer connectivity if disrupted
2. Close MCP client connections
