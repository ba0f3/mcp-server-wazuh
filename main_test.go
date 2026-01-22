package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/mcp-server-wazuh/internal/testutils"
	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPProtocolInitialization(t *testing.T) {
	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	t1, t2 := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		if _, err := s.Connect(ctx, t1, nil); err != nil {
			// can't t.Fatalf here since it's a goroutine
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer session.Close()

	// Protocol version negotiation is handled internally by Connect
}

func TestToolsList(t *testing.T) {
	mockServer := testutils.NewMockWazuhServer("success")
	defer mockServer.Close()

	// Use mock server URL directly
	wazuhClient := wazuh.NewClient(mockServer.URL(), 0, "wazuh", "wazuh", mockServer.URL(), 0, "admin", "admin", false)
	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	registerTools(s, wazuhClient)

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

	var tools []*mcp.Tool
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("failed to list tools: %v", err)
		}
		tools = append(tools, tool)
	}

	if len(tools) == 0 {
		t.Errorf("expected tools, got none")
	}

	found := false
	for _, tool := range tools {
		if tool.Name == "get_wazuh_alert_summary" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("get_wazuh_alert_summary tool not found")
	}
}

func TestGetWazuhAlertSummarySuccess(t *testing.T) {
	mockServer := testutils.NewMockWazuhServer("success")
	defer mockServer.Close()

	wazuhClient := wazuh.NewClient(mockServer.URL(), 0, "wazuh", "wazuh", mockServer.URL(), 0, "admin", "admin", false)
	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	registerTools(s, wazuhClient)

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

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_wazuh_alert_summary",
		Arguments: map[string]interface{}{"limit": 2},
	})

	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	if res.IsError {
		t.Errorf("expected success, got error")
	}

	if len(res.Content) == 0 {
		t.Errorf("expected content, got none")
	}

	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "Alert ID:") {
		t.Errorf("expected Alert ID in output, got: %s", text)
	}
}

func TestGetWazuhAlertSummaryEmpty(t *testing.T) {
	mockServer := testutils.NewMockWazuhServer("empty_alerts")
	defer mockServer.Close()

	wazuhClient := wazuh.NewClient(mockServer.URL(), 0, "wazuh", "wazuh", mockServer.URL(), 0, "admin", "admin", false)
	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	registerTools(s, wazuhClient)

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

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_wazuh_alert_summary",
		Arguments: map[string]interface{}{},
	})

	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	text := res.Content[0].(*mcp.TextContent).Text
	if text != "No Wazuh alerts found." {
		t.Errorf("expected 'No Wazuh alerts found.', got: %s", text)
	}
}

func TestGetWazuhAlertSummaryError(t *testing.T) {
	mockServer := testutils.NewMockWazuhServer("alerts_error")
	defer mockServer.Close()

	wazuhClient := wazuh.NewClient(mockServer.URL(), 0, "wazuh", "wazuh", mockServer.URL(), 0, "admin", "admin", false)
	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	registerTools(s, wazuhClient)

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

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_wazuh_alert_summary",
		Arguments: map[string]interface{}{},
	})

	if err != nil {
		t.Fatalf("failed to call tool: %v", err)
	}

	if !res.IsError {
		t.Errorf("expected error, got success")
	}

	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "Error retrieving alerts") {
		t.Errorf("expected error message, got: %s", text)
	}
}
