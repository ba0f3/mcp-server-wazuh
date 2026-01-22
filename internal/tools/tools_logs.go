package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerLogTools(s *mcp.Server, client *wazuh.Client) {
	// search_wazuh_manager_logs
	type SearchLogsInput struct {
		Query string `json:"query" jsonschema:"description:Search query for manager logs"`
		Limit int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_wazuh_manager_logs",
		Description: "Perform search across Wazuh manager internal logs for troubleshooting",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in SearchLogsInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		logs, err := client.GetManagerLogs(limit, 0, "", "", in.Query)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Manager Logs:\n%s", prettyJSON(logs))}},
		}, nil, nil
	})

	// get_wazuh_manager_error_logs
	type LimitInput struct {
		Limit int `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 50)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_manager_error_logs",
		Description: "Specifically retrieve error-level logs from the Wazuh manager",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in LimitInput) (*mcp.CallToolResult, any, error) {
		limit := 50
		if in.Limit > 0 {
			limit = in.Limit
		}
		logs, err := client.GetManagerLogs(limit, 0, "error", "", "")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Manager Error Logs:\n%s", prettyJSON(logs))}},
		}, nil, nil
	})

	// validate_wazuh_connection
	mcp.AddTool(s, &mcp.Tool{
		Name:        "validate_wazuh_connection",
		Description: "Verify the connection and authentication between the MCP server and Wazuh API",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		result, err := client.ValidateConnection()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Connection Validation:\n%s", prettyJSON(result))}},
		}, nil, nil
	})
}
