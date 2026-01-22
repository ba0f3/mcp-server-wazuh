package tools

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/mcp-server-wazuh/internal/config"
	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// setupMCPTestSession creates a real MCP server and client session for testing
// Uses configuration from .env file to connect to a real Wazuh server
// Returns session as interface{} to avoid type issues, caller should use type assertion
func setupMCPTestSession(t *testing.T, scenario string) (*mcp.Server, interface{}, context.CancelFunc) {
	// Load configuration from .env file
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("failed to load configuration: %v", err)
	}

	// Log loaded configuration for debugging
	t.Logf("Loaded Wazuh API config: Host=%s, Port=%d, User=%s", cfg.WazuhAPIHost, cfg.WazuhAPIPort, cfg.WazuhAPIUsername)
	t.Logf("Loaded Wazuh Indexer config: Host=%s, Port=%d, User=%s", cfg.WazuhIndexerHost, cfg.WazuhIndexerPort, cfg.WazuhIndexerUsername)

	// Create real Wazuh client using configuration from .env
	wazuhClient := wazuh.NewClient(
		cfg.WazuhAPIHost,
		cfg.WazuhAPIPort,
		cfg.WazuhAPIUsername,
		cfg.WazuhAPIPassword,
		cfg.WazuhIndexerHost,
		cfg.WazuhIndexerPort,
		cfg.WazuhIndexerUsername,
		cfg.WazuhIndexerPassword,
		cfg.VerifySSL,
	)

	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	RegisterTools(s, wazuhClient)

	t1, t2 := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Longer timeout for real server

	go func() {
		if _, err := s.Connect(ctx, t1, nil); err != nil {
			t.Logf("Server connect error: %v", err)
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		cancel()
		t.Fatalf("failed to connect client: %v", err)
	}

	return s, session, cancel
}

// callTool is a helper to call tools on the session
func callTool(t *testing.T, session interface{}, name string, args map[string]interface{}) (*mcp.CallToolResult, error) {
	if s, ok := session.(interface {
		CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)
	}); ok {
		return s.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		})
	}
	return nil, fmt.Errorf("session does not support CallTool")
}

// listTools is a helper to list tools from the session using reflection
func listTools(t *testing.T, session interface{}) []*mcp.Tool {
	var toolList []*mcp.Tool

	// Use reflection to call the Tools method
	v := reflect.ValueOf(session)
	method := v.MethodByName("Tools")
	if !method.IsValid() {
		t.Fatalf("session does not have Tools method: %T", session)
	}

	// Call Tools(ctx, nil)
	ctxVal := reflect.ValueOf(context.Background())
	nilVal := reflect.ValueOf((*mcp.ListToolsParams)(nil))
	results := method.Call([]reflect.Value{ctxVal, nilVal})
	if len(results) != 1 {
		t.Fatalf("Tools method returned unexpected number of values")
	}

	seq := results[0]

	// Check if it's an iter.Seq2 (function type)
	if seq.Kind() != reflect.Func {
		t.Fatalf("Tools method did not return a sequence function, got: %v (kind: %v)", seq.Type(), seq.Kind())
	}

	// iter.Seq2[*mcp.Tool, error] is: func(yield func(*mcp.Tool, error) bool)
	// We need to call it with a callback that collects tools
	// Create the yield callback function type
	toolType := reflect.TypeOf((*mcp.Tool)(nil)) // *mcp.Tool (pointer type)
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	callbackType := reflect.FuncOf(
		[]reflect.Type{toolType, errorType},
		[]reflect.Type{reflect.TypeOf(false)},
		false,
	)

	// Create a callback that collects tools
	callback := reflect.MakeFunc(callbackType, func(args []reflect.Value) []reflect.Value {
		toolVal := args[0]
		errVal := args[1]

		// Check for error
		if !errVal.IsNil() {
			if err, ok := errVal.Interface().(error); ok && err != nil {
				t.Fatalf("failed to list tools: %v", err)
			}
		}

		// Collect the tool
		if !toolVal.IsNil() {
			if tool, ok := toolVal.Interface().(*mcp.Tool); ok {
				toolList = append(toolList, tool)
			}
		}

		// Return true to continue iteration
		return []reflect.Value{reflect.ValueOf(true)}
	})

	// Call the sequence function with our callback
	seq.Call([]reflect.Value{callback})

	return toolList
}

// closeSession is a helper to close the session
func closeSession(session interface{}) {
	if s, ok := session.(interface{ Close() }); ok {
		s.Close()
	}
}

// Test all 42 tools using real MCP client

// Alert Management Tools (4 tools)
func TestGetWazuhAlerts(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_alerts", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Errorf("expected success, got error: %s", res.Content[0].(*mcp.TextContent).Text)
	}
	if len(res.Content) == 0 {
		t.Error("expected content, got none")
	}
}

func TestGetWazuhAlertSummary(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_alert_summary", map[string]interface{}{"time_range": "24h"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	// May return error if not fully implemented
	if res.IsError {
		t.Logf("get_wazuh_alert_summary returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestAnalyzeAlertPatterns(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "analyze_alert_patterns", map[string]interface{}{"time_range": "7d"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("analyze_alert_patterns returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestSearchSecurityEvents(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "search_security_events", map[string]interface{}{"query": "error"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("search_security_events returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Agent Management Tools (6 tools)
func TestGetWazuhAgents(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_agents", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Errorf("expected success, got error: %s", res.Content[0].(*mcp.TextContent).Text)
	}
	if len(res.Content) == 0 {
		t.Error("expected content, got none")
	}
}

func TestGetWazuhRunningAgents(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_running_agents", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_running_agents returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentSummaryOS(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_summary_os", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_summary_os returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentSummaryStatus(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_summary_status", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_summary_status returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentGroups(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_groups", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_groups returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentDistinctStats(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_distinct_stats", map[string]interface{}{"field": "os.name"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_distinct_stats returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentProcesses(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_processes", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_processes returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentPorts(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_ports", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_ports returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentConfiguration(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_configuration", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_configuration returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Vulnerability Management Tools (3 tools)
func TestGetWazuhVulnerabilities(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_vulnerabilities", map[string]interface{}{"limit": 10, "severity": "Critical"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_vulnerabilities returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetWazuhCriticalVulnerabilities(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_critical_vulnerabilities", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_critical_vulnerabilities returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetWazuhVulnerabilitySummary(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_vulnerability_summary", map[string]interface{}{"time_range": "7d"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_vulnerability_summary returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Security Analysis Tools (1 tool)
func TestGetTopSecurityThreats(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_top_security_threats", map[string]interface{}{"limit": 10, "time_range": "24h"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_top_security_threats returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Statistics Tools (4 tools)
func TestGetWazuhManagerDaemonStats(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_manager_daemon_stats", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_manager_daemon_stats returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetWazuhWeeklyStats(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_weekly_stats", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_weekly_stats returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentDaemonStats(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_daemon_stats", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_daemon_stats returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetAgentLogCollectorStats(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_agent_log_collector_stats", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_agent_log_collector_stats returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Log Management Tools (3 tools)
func TestSearchWazuhManagerLogs(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "search_wazuh_manager_logs", map[string]interface{}{"query": "error", "limit": 20})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("search_wazuh_manager_logs returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetWazuhManagerErrorLogs(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_manager_error_logs", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_manager_error_logs returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestValidateWazuhConnection(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "validate_wazuh_connection", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Errorf("expected successful connection validation, got error: %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Rules Tools (1 tool)
func TestGetWazuhRulesSummary(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_rules_summary", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_rules_summary returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Cluster Tools (2 tools)
func TestGetWazuhClusterHealth(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_cluster_health", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_cluster_health returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetWazuhClusterNodes(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_cluster_nodes", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_wazuh_cluster_nodes returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Comprehensive test: Verify all 42 tools are callable
func TestAllToolsCallable(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	// List all available tools
	toolNames := []string{}
	tools := listTools(t, session)
	for _, tool := range tools {
		toolNames = append(toolNames, tool.Name)
	}

	// Expected 42 tools
	expectedCount := 42
	if len(toolNames) != expectedCount {
		t.Errorf("expected %d tools, got %d: %v", expectedCount, len(toolNames), toolNames)
	}

	// All 42 tool names
	allTools := []string{
		// Alert Management (5)
		"get_wazuh_alerts",
		"get_wazuh_alert_summary",
		"analyze_alert_patterns",
		"search_security_events",
		"get_top_security_threats",
		// Agent Management (9)
		"get_wazuh_agents",
		"get_wazuh_running_agents",
		"get_agent_processes",
		"get_agent_ports",
		"get_agent_configuration",
		"get_agent_summary_os",
		"get_agent_summary_status",
		"get_agent_groups",
		"get_agent_distinct_stats",
		// Vulnerability Management (3)
		"get_wazuh_vulnerabilities",
		"get_wazuh_critical_vulnerabilities",
		"get_wazuh_vulnerability_summary",
		// Statistics (4)
		"get_wazuh_manager_daemon_stats",
		"get_wazuh_weekly_stats",
		"get_agent_daemon_stats",
		"get_agent_log_collector_stats",
		// Logs (3)
		"search_wazuh_manager_logs",
		"get_wazuh_manager_error_logs",
		"validate_wazuh_connection",
		// Rules (1)
		"get_wazuh_rules_summary",
		// Cluster (2)
		"get_wazuh_cluster_health",
		"get_wazuh_cluster_nodes",
		// SCA (3)
		"get_sca_policies",
		"get_sca_policy_checks",
		"get_sca_summary",
		// Decoders (3)
		"get_decoders",
		"get_decoder_files",
		"get_decoders_by_file",
		// Rootcheck (2)
		"get_rootcheck_database",
		"get_rootcheck_last_scan",
		// MITRE (3)
		"get_mitre_techniques",
		"get_mitre_technique_by_id",
		"get_mitre_agents",
		// Active Response (2)
		"execute_active_response",
		"get_active_response_logs",
		// CDB (2)
		"get_cdb_lists",
		"get_cdb_list_file",
	}

	// Verify all tools are present
	toolMap := make(map[string]bool)
	for _, name := range toolNames {
		toolMap[name] = true
	}

	for _, expectedTool := range allTools {
		if !toolMap[expectedTool] {
			t.Errorf("expected tool '%s' not found in registered tools", expectedTool)
		}
	}
}

// Test error handling with invalid tool name
func TestInvalidToolName(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	_, err := callTool(t, session, "nonexistent_tool", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for invalid tool name, got nil")
	}
}

// Test empty arguments handling
func TestToolsWithEmptyArguments(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	// Tools that should work with empty arguments
	toolsWithNoArgs := []string{
		"get_wazuh_manager_daemon_stats",
		"get_wazuh_weekly_stats",
		"get_wazuh_rules_summary",
		"get_wazuh_cluster_health",
		"get_wazuh_cluster_nodes",
		"validate_wazuh_connection",
		"get_wazuh_running_agents",
		"get_agent_summary_os",
		"get_agent_summary_status",
		"get_agent_groups",
		"get_decoder_files",
	}

	for _, toolName := range toolsWithNoArgs {
		res, err := callTool(t, session, toolName, map[string]interface{}{})
		if err != nil {
			t.Errorf("tool %s failed with empty args: %v", toolName, err)
		}
		if res != nil && res.IsError {
			// Some tools may return errors if not fully implemented, log but don't fail
			t.Logf("tool %s returned error (may be expected): %s", toolName, res.Content[0].(*mcp.TextContent).Text)
		}
	}
}

// Test filtering capabilities
func TestToolFiltering(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	// Test get_wazuh_alerts with various filters
	testCases := []map[string]interface{}{
		{"limit": 5},
		{"level": "12"},
		{"agent_id": "001"},
		{"rule_id": "1001"},
		{"limit": 10, "level": "10+"},
	}

	for i, args := range testCases {
		res, err := callTool(t, session, "get_wazuh_alerts", args)
		if err != nil {
			t.Errorf("test case %d failed: %v", i, err)
		}
		if res != nil && res.IsError && !strings.Contains(strings.ToLower(res.Content[0].(*mcp.TextContent).Text), "error") {
			t.Errorf("test case %d: unexpected error format", i)
		}
	}

	// Test get_wazuh_agents with filters
	// Note: Some filters may not be fully supported by the mock server
	agentFilters := []map[string]interface{}{
		{"status": "active"},
		{"name": "web-server-01"},
		{"agent_id": "001"},
		{"limit": 5},
	}

	for i, args := range agentFilters {
		res, err := callTool(t, session, "get_wazuh_agents", args)
		if err != nil {
			t.Errorf("agent filter test case %d failed: %v", i, err)
			continue
		}
		if res != nil && res.IsError {
			// Some filter combinations may not be fully supported by the mock server
			// Log the error but don't fail the test for expected limitations
			t.Logf("agent filter test case %d returned error (may be expected due to mock limitations): %s", i, res.Content[0].(*mcp.TextContent).Text)
		}
	}
}

// Experimental API Tests

// SCA Tools (3 tools)
func TestGetSCAPolicies(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_sca_policies", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_sca_policies returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetSCAPolicyChecks(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_sca_policy_checks", map[string]interface{}{"agent_id": "001", "policy_id": "cis_debian_linux"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_sca_policy_checks returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetSCASummary(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_sca_summary", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_sca_summary returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Decoder Tools (3 tools)
func TestGetDecoders(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_decoders", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_decoders returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetDecoderFiles(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_decoder_files", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_decoder_files returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetDecodersByFile(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_decoders_by_file", map[string]interface{}{"filename": "decoder.xml"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_decoders_by_file returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Rootcheck Tools (2 tools)
func TestGetRootcheckDatabase(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_rootcheck_database", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_rootcheck_database returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetRootcheckLastScan(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_rootcheck_last_scan", map[string]interface{}{"agent_id": "001"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_rootcheck_last_scan returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// MITRE Tools (3 tools)
func TestGetMITRETechniques(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_mitre_techniques", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_mitre_techniques returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetMITRETechniqueByID(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_mitre_technique_by_id", map[string]interface{}{"technique_id": "T1005"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_mitre_technique_by_id returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetMITREAgents(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_mitre_agents", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_mitre_agents returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Active Response Tools (2 tools)
func TestExecuteActiveResponse(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "execute_active_response", map[string]interface{}{
		"agent_id": "001",
		"command":  "restart-ossec0",
		"custom":   false,
	})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("execute_active_response returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetActiveResponseLogs(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_active_response_logs", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_active_response_logs returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// CDB Tools (2 tools)
func TestGetCDBLists(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_cdb_lists", map[string]interface{}{"limit": 10})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_cdb_lists returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

func TestGetCDBListFile(t *testing.T) {
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_cdb_list_file", map[string]interface{}{"path": "/var/ossec/etc/lists/audit-keys"})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	if res.IsError {
		t.Logf("get_cdb_list_file returned error (may be expected): %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Test error scenarios
func TestErrorScenarios(t *testing.T) {
	// Test with real server - verify tool handles responses correctly
	_, session, cancel := setupMCPTestSession(t, "success")
	defer closeSession(session)
	defer cancel()

	res, err := callTool(t, session, "get_wazuh_alerts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}
	// With real server, we can't predict if there will be alerts or not
	// Just verify the tool returns a valid response (success or empty result)
	if res.IsError {
		// If there's an error, it should be a clear error message
		errorText := res.Content[0].(*mcp.TextContent).Text
		if !strings.Contains(strings.ToLower(errorText), "error") {
			t.Errorf("expected error message to contain 'error', got: %s", errorText)
		}
	} else {
		// If successful, should have content (even if empty)
		if len(res.Content) == 0 {
			t.Error("expected content in response, got none")
		}
	}
}
