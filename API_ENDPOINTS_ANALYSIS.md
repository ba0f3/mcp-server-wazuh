# Wazuh API Endpoints Analysis

## Summary
Many endpoints used in this codebase do not exist in the standard Wazuh API. According to the [Wazuh API documentation](https://documentation.wazuh.com/current/user-manual/api/index.html), these are custom/hypothetical endpoints that return 404 errors.

**Note**: Wazuh has two separate APIs:
- **Wazuh Server API** (port 55000) - For manager operations, agents, rules, etc.
- **Wazuh Indexer API** (port 9200) - For searching alerts and indexed data (Elasticsearch/OpenSearch compatible)

Some features should use the Indexer API instead of trying to use non-existent Server API endpoints.

## Non-Existent Endpoints (Returning 404)

### Security Endpoints (All Custom - Don't Exist)
1. **`POST /security/threat/analyze`** - Security threat analysis
   - Status: ❌ Not in standard Wazuh API
   - Used in: `AnalyzeSecurityThreat()`
   - Alternative: Use existing alerts API and analyze locally

2. **`GET /security/ioc/reputation`** - IOC reputation check
   - Status: ❌ Not in standard Wazuh API
   - Used in: `CheckIOCReputation()`
   - Alternative: Integrate with external threat intelligence APIs

3. **`GET /security/risk`** - Risk assessment
   - Status: ❌ Not in standard Wazuh API
   - Used in: `PerformRiskAssessment()`
   - Alternative: Calculate risk from existing agent/alerts data

4. **`POST /security/reports/generate`** - Security report generation
   - Status: ❌ Not in standard Wazuh API
   - Used in: `GenerateSecurityReport()`
   - Alternative: Generate reports from existing API data

5. **`POST /security/compliance/check`** - Compliance checking
   - Status: ❌ Not in standard Wazuh API
   - Used in: `RunComplianceCheck()`
   - Alternative: Use SCA (Security Configuration Assessment) endpoints

### Agent Endpoints (Some Custom)
1. **`GET /agents/{agent_id}/health`** - Agent health check
   - Status: ❌ Not in standard Wazuh API
   - Used in: `CheckAgentHealth()`
   - Alternative: Use `/agents/{agent_id}` and check status field, or use `/agents/{agent_id}/daemons/stats`

2. **`GET /agents/{agent_id}/config`** - Agent configuration
   - Status: ⚠️ Partially exists - requires component and configuration parameters
   - Actual endpoint: `GET /agents/{agent_id}/config/{component}/{configuration}`
   - Used in: `GetAgentConfiguration()`
   - Issue: Current implementation doesn't specify component/configuration
   - Alternative: Use the correct endpoint format with component and configuration parameters

### Statistics Endpoints (Some May Not Exist)
1. **`GET /rules/summary`** - Rules summary
   - Status: ⚠️ Unclear - may not exist
   - Used in: `GetRulesSummary()`
   - Alternative: Use `/rules` endpoint and aggregate locally

2. **`GET /manager/stats/all`** - Manager statistics
   - Status: ⚠️ Deprecated in Wazuh 4.4.0
   - Used in: `GetWazuhStatistics()`
   - Alternative: Use `GET /manager/daemons/stats` (new endpoint since 4.4.0)
   - Reference: [Wazuh 4.4.0 Release Notes](https://documentation.wazuh.com/current/release-notes/release-4-4-0.html)

3. **`GET /manager/stats/logcollector`** - Log collector stats
   - Status: ⚠️ Deprecated in Wazuh 4.4.0
   - Used in: `GetLogCollectorStats()`
   - Alternative: Use `GET /manager/daemons/stats` or `GET /agents/{agent_id}/stats/logcollector`
   - Note: The old `/manager/stats/analysisd` and `/manager/stats/remoted` were also deprecated

## Valid Endpoints (Working)

### Agent Management
- ✅ `GET /agents` - List agents ([API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html))
- ✅ `GET /agents/{agent_id}` - Get agent info
- ✅ `GET /agents/{agent_id}/stats/logcollector` - Agent log collector stats
- ✅ `GET /agents/{agent_id}/daemons/stats` - Agent daemon statistics
- ✅ `GET /agents/{agent_id}/config/{component}/{configuration}` - Query remote agent configuration
- ✅ `GET /agents/stats/distinct` - Distinct agent statistics
- ✅ `GET /agents/summary/os` - OS summary
- ✅ `GET /agents/summary/status` - Status summary

### Statistics
- ✅ `GET /manager/daemons/stats` - Manager daemon statistics (replaces deprecated endpoints)
- ⚠️ `GET /manager/stats/weekly` - Weekly statistics (may still work but check version)
- ⚠️ `GET /manager/stats/remoted` - Remoted statistics (deprecated in 4.4.0, use `/manager/daemons/stats`)
- ⚠️ `GET /manager/stats/all` - All statistics (deprecated in 4.4.0, use `/manager/daemons/stats`)

### Rules
- ✅ `GET /rules` - List rules
- ✅ `GET /rules/{rule_id}` - Get specific rule

### Cluster
- ✅ `GET /cluster/health` - Cluster health
- ✅ `GET /cluster/nodes` - Cluster nodes

### Logs
- ✅ `GET /manager/logs` - Manager logs

### Indexer API (Elasticsearch/OpenSearch Compatible)
- ✅ `POST /wazuh-alerts-*/_search` - Search alerts (used correctly in `GetAlerts()`, `SearchSecurityEvents()`, etc.)
- ✅ `POST /wazuh-alerts-*/_search` with aggregations - For pattern analysis and threat detection
- Note: The codebase correctly uses the Indexer API for alert searching, which is the right approach

## Recommendations

1. **Remove or Refactor Custom Endpoints**: The security-related endpoints (`/security/*`) should be refactored to use existing Wazuh API endpoints combined with local processing.

2. **Use Existing Endpoints**: For features like threat analysis, risk assessment, and compliance checking, use existing endpoints like:
   - `/agents` for agent data (Server API)
   - Alerts from **Indexer API** (`/wazuh-alerts-*/_search`) for threat analysis
   - SCA endpoints for compliance (Server API)
   - Rules API for security analysis (Server API)
   - **Indexer API** for searching and aggregating alert data

3. **Use Indexer API for Alert Analysis**: Many security analysis features should query the Wazuh Indexer API (Elasticsearch-compatible) instead of non-existent Server API endpoints:
   - Threat analysis → Query indexer for alerts by rule/severity
   - IOC reputation → Search alerts for indicators
   - Risk assessment → Aggregate alerts and agent data
   - Security reports → Query and aggregate from indexer

4. **Implement Locally**: Many of these "missing" features can be implemented by:
   - Querying existing Server API endpoints for agent/rules data
   - Querying Indexer API for alert/search data
   - Processing and aggregating data locally
   - Combining results from both APIs

5. **Update Deprecated Endpoints**: Replace deprecated endpoints:
   - `GET /manager/stats/all` → `GET /manager/daemons/stats`
   - `GET /manager/stats/remoted` → `GET /manager/daemons/stats`
   - `GET /manager/stats/analysisd` → `GET /manager/daemons/stats`

6. **Document Limitations**: Clearly document which features require custom implementations vs. using standard Wazuh API endpoints.

## References
- [Wazuh Server API Documentation](https://documentation.wazuh.com/current/user-manual/api/index.html)
- [Wazuh Server API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh Indexer API Reference](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html)
- [Wazuh 4.4.0 Release Notes - API Deprecations](https://documentation.wazuh.com/current/release-notes/release-4-4-0.html)
- [RBAC Reference](https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html)
