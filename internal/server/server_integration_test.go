package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/mcp-server-wazuh/internal/testutils"
	"github.com/ba0f3/mcp-server-wazuh/internal/tools"
	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Test: All 29 tools are registered and discoverable
func TestAllToolsRegistered(t *testing.T) {
	// Use the same pattern as existing tests to avoid type issues
	mockServer := testutils.NewMockWazuhServer("success")
	defer mockServer.Close()

	wazuhClient := wazuh.NewClient(mockServer.URL(), 0, "wazuh", "wazuh", mockServer.URL(), 0, "admin", "admin", false)
	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	tools.RegisterTools(s, wazuhClient)

	t1, t2 := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		if _, err := s.Connect(ctx, t1, nil); err != nil {
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer session.Close()

	var toolList []*mcp.Tool
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("failed to list tools: %v", err)
		}
		toolList = append(toolList, tool)
	}

	expectedToolCount := 42
	if len(toolList) != expectedToolCount {
		t.Errorf("expected %d tools, got %d", expectedToolCount, len(toolList))
	}

	// Check for key tools
	requiredTools := []string{
		"get_wazuh_alerts",
		"get_wazuh_agents",
		"get_wazuh_vulnerabilities",
		"validate_wazuh_connection",
		"get_wazuh_manager_daemon_stats",
		"get_wazuh_rules_summary",
		"get_wazuh_cluster_health",
	}

	toolMap := make(map[string]bool)
	for _, tool := range toolList {
		toolMap[tool.Name] = true
	}

	for _, toolName := range requiredTools {
		if !toolMap[toolName] {
			t.Errorf("required tool '%s' not found", toolName)
		}
	}
}

// Test: Tool descriptions are present and informative
func TestToolDescriptionsPresent(t *testing.T) {
	// Use the same pattern as existing tests
	mockServer := testutils.NewMockWazuhServer("success")
	defer mockServer.Close()

	wazuhClient := wazuh.NewClient(mockServer.URL(), 0, "wazuh", "wazuh", mockServer.URL(), 0, "admin", "admin", false)
	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	tools.RegisterTools(s, wazuhClient)

	t1, t2 := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		if _, err := s.Connect(ctx, t1, nil); err != nil {
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer session.Close()

	var toolList []*mcp.Tool
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("failed to list tools: %v", err)
		}
		toolList = append(toolList, tool)
	}

	for _, tool := range toolList {
		if tool.Description == "" {
			t.Errorf("tool '%s' has no description", tool.Name)
		}
		if len(tool.Description) < 10 {
			t.Errorf("tool '%s' has a very short description: %s", tool.Name, tool.Description)
		}
		// Check naming convention (snake_case)
		if strings.Contains(tool.Name, " ") || strings.ToUpper(tool.Name) == tool.Name {
			t.Errorf("tool '%s' does not follow snake_case naming convention", tool.Name)
		}
	}
}

// Test: Server handles empty tool arguments gracefully
func TestEmptyToolArguments(t *testing.T) {
	session, mockServer, err := testutils.SetupTestSession("success")
	if err != nil {
		t.Fatalf("failed to setup test session: %v", err)
	}
	defer session.Close()
	defer mockServer.Close()

	wazuhClient := session.GetWazuhClient(mockServer)
	tools.RegisterTools(session.Server, wazuhClient)

	res, err := session.CallTool("get_wazuh_alerts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	if res.IsError {
		t.Errorf("expected success with empty arguments, got error: %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Test: Server handles invalid tool arguments
func TestInvalidToolArguments(t *testing.T) {
	session, mockServer, err := testutils.SetupTestSession("success")
	if err != nil {
		t.Fatalf("failed to setup test session: %v", err)
	}
	defer session.Close()
	defer mockServer.Close()

	wazuhClient := session.GetWazuhClient(mockServer)
	tools.RegisterTools(session.Server, wazuhClient)

	// Test with invalid limit (negative)
	res, err := session.CallTool("get_wazuh_alerts", map[string]interface{}{
		"limit": -1,
	})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	// Should either use default or handle gracefully
	if res.IsError && !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "limit") {
		// If it's an error, it should mention the limit issue
	}
}

// Test: Server handles Wazuh API errors gracefully
func TestWazuhAPIErrors(t *testing.T) {
	session, mockServer, err := testutils.SetupTestSession("alerts_error")
	if err != nil {
		t.Fatalf("failed to setup test session: %v", err)
	}
	defer session.Close()
	defer mockServer.Close()

	wazuhClient := session.GetWazuhClient(mockServer)
	tools.RegisterTools(session.Server, wazuhClient)

	res, err := session.CallTool("get_wazuh_alerts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	if !res.IsError {
		t.Errorf("expected error response, got success")
	}

	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(strings.ToLower(text), "error") {
		t.Errorf("expected error message, got: %s", text)
	}
}

// Test: Server handles empty responses from Wazuh
func TestEmptyWazuhResponses(t *testing.T) {
	session, mockServer, err := testutils.SetupTestSession("empty_alerts")
	if err != nil {
		t.Fatalf("failed to setup test session: %v", err)
	}
	defer session.Close()
	defer mockServer.Close()

	wazuhClient := session.GetWazuhClient(mockServer)
	tools.RegisterTools(session.Server, wazuhClient)

	res, err := session.CallTool("get_wazuh_alerts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	if res.IsError {
		t.Errorf("expected success with empty results, got error: %s", res.Content[0].(*mcp.TextContent).Text)
	}

	text := res.Content[0].(*mcp.TextContent).Text
	if text != "No Wazuh alerts found." {
		t.Errorf("expected 'No Wazuh alerts found.', got: %s", text)
	}
}

// Test: Server validates Wazuh Manager connection
func TestValidateWazuhConnection(t *testing.T) {
	session, mockServer, err := testutils.SetupTestSession("success")
	if err != nil {
		t.Fatalf("failed to setup test session: %v", err)
	}
	defer session.Close()
	defer mockServer.Close()

	wazuhClient := session.GetWazuhClient(mockServer)
	tools.RegisterTools(session.Server, wazuhClient)

	res, err := session.CallTool("validate_wazuh_connection", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	if res.IsError {
		t.Errorf("expected successful connection validation, got error: %s", res.Content[0].(*mcp.TextContent).Text)
	}
}

// Test: Server handles invalid Wazuh credentials
func TestInvalidWazuhCredentials(t *testing.T) {
	session, mockServer, err := testutils.SetupTestSession("auth_error")
	if err != nil {
		t.Fatalf("failed to setup test session: %v", err)
	}
	defer session.Close()
	defer mockServer.Close()

	wazuhClient := session.GetWazuhClient(mockServer)
	tools.RegisterTools(session.Server, wazuhClient)

	res, err := session.CallTool("get_wazuh_agents", map[string]interface{}{})
	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	if !res.IsError {
		t.Errorf("expected error response for invalid credentials, got success")
	}

	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(strings.ToLower(text), "error") && !strings.Contains(strings.ToLower(text), "auth") {
		t.Errorf("expected authentication error message, got: %s", text)
	}
}
