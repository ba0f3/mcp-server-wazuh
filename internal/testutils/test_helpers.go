package testutils

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestSession represents an MCP test session with server and client
type TestSession struct {
	Server  *mcp.Server
	Client  *mcp.Client
	Session interface{} // Session from client.Connect() - use type assertion in methods
	Context context.Context
	Cancel  context.CancelFunc
}

// SetupTestSession creates a new MCP test session with mock Wazuh server
// Note: tools.RegisterTools must be called separately to avoid import cycle
func SetupTestSession(scenario string) (*TestSession, *MockWazuhServer, error) {
	mockServer := NewMockWazuhServer(scenario)

	s := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.0.0"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	go func() {
		if _, err := s.Connect(ctx, t1, nil); err != nil {
			// Error handling in test
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		cancel()
		mockServer.Close()
		return nil, nil, err
	}

	return &TestSession{
		Server:  s,
		Client:  client,
		Session: session,
		Context: ctx,
		Cancel:  cancel,
	}, mockServer, nil
}

// GetWazuhClient returns a Wazuh client configured for the mock server
func (ts *TestSession) GetWazuhClient(mockServer *MockWazuhServer) *wazuh.Client {
	return wazuh.NewClient(
		mockServer.URL(), 0, "wazuh", "wazuh",
		mockServer.URL(), 0, "admin", "admin", false,
	)
}

// Close closes the test session and cleans up resources
func (ts *TestSession) Close() {
	if ts.Session != nil {
		if closer, ok := ts.Session.(interface{ Close() }); ok {
			closer.Close()
		}
	}
	if ts.Cancel != nil {
		ts.Cancel()
	}
}

// CallTool is a helper to call an MCP tool and return the result
func (ts *TestSession) CallTool(name string, args map[string]interface{}) (*mcp.CallToolResult, error) {
	if caller, ok := ts.Session.(interface {
		CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)
	}); ok {
		return caller.CallTool(ts.Context, &mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		})
	}
	return nil, fmt.Errorf("session does not support CallTool")
}

// ListTools returns all available tools
func (ts *TestSession) ListTools() ([]*mcp.Tool, error) {
	// The session.Tools() method returns a channel that can be iterated with:
	// for tool, err := range session.Tools(ctx, nil)
	// We need to use reflection to call this method since we store Session as interface{}
	var toolList []*mcp.Tool

	// Use reflection to call the Tools method
	v := reflect.ValueOf(ts.Session)
	method := v.MethodByName("Tools")
	if !method.IsValid() {
		return nil, fmt.Errorf("session does not have Tools method: %T", ts.Session)
	}

	// Call Tools(ctx, nil)
	ctxVal := reflect.ValueOf(ts.Context)
	nilVal := reflect.ValueOf((*mcp.ListToolsParams)(nil))
	results := method.Call([]reflect.Value{ctxVal, nilVal})
	if len(results) != 1 {
		return nil, fmt.Errorf("Tools method returned unexpected number of values")
	}

	ch := results[0]
	if ch.Kind() != reflect.Chan {
		return nil, fmt.Errorf("Tools method did not return a channel")
	}

	// Iterate over the channel
	for {
		recv, ok := ch.Recv()
		if !ok {
			break // Channel closed
		}

		// The channel yields values that can be destructured as (tool, err)
		// Try to extract tool and err from the received value
		if recv.Kind() == reflect.Struct && recv.NumField() >= 2 {
			toolField := recv.Field(0)
			errField := recv.Field(1)

			if !errField.IsNil() {
				err := errField.Interface().(error)
				return nil, err
			}

			if toolField.IsValid() && !toolField.IsNil() {
				tool := toolField.Interface().(*mcp.Tool)
				toolList = append(toolList, tool)
			}
		} else {
			// Try direct value extraction
			if recv.CanInterface() {
				if tool, ok := recv.Interface().(*mcp.Tool); ok {
					toolList = append(toolList, tool)
				}
			}
		}
	}

	return toolList, nil
}
