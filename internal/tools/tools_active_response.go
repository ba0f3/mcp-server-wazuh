package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerActiveResponseTools(s *mcp.Server, client *wazuh.Client) {
	// execute_active_response
	type ExecuteActiveResponseInput struct {
		AgentID string   `json:"agent_id,omitempty" jsonschema:"description:Target agent ID (empty for all agents)"`
		Command string   `json:"command" jsonschema:"description:Active response command to execute"`
		Custom  bool     `json:"custom,omitempty" jsonschema:"description:Whether this is a custom command"`
		Args    []string `json:"args,omitempty" jsonschema:"description:Command arguments"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "execute_active_response",
		Description: "Execute an active response command on an agent or all agents",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in ExecuteActiveResponseInput) (*mcp.CallToolResult, any, error) {
		command := wazuh.ActiveResponseCommand{
			Command:    in.Command,
			Custom:     in.Custom,
			Args:       in.Args,
			ExtraArgs:  make(map[string]interface{}),
		}
		result, err := client.ExecuteActiveResponse(in.AgentID, command)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Active Response Result:\n%s", prettyJSON(result))}},
		}, nil, nil
	})

	// get_active_response_logs
	type GetActiveResponseLogsInput struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Sort   string `json:"sort,omitempty" jsonschema:"description:Sort field"`
		Search string `json:"search,omitempty" jsonschema:"description:Search term"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_active_response_logs",
		Description: "Retrieve active response execution logs",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetActiveResponseLogsInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		result, err := client.GetActiveResponseLogs(limit, in.Offset, in.Sort, in.Search)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Active Response Logs:\n%s", prettyJSON(result))}},
		}, nil, nil
	})
}
