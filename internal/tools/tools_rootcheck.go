package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerRootcheckTools(s *mcp.Server, client *wazuh.Client) {
	// get_rootcheck_database
	type GetRootcheckInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Target agent ID"`
		Limit   int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset  int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Sort    string `json:"sort,omitempty" jsonschema:"description:Sort field"`
		Search  string `json:"search,omitempty" jsonschema:"description:Search term"`
		Status  string `json:"status,omitempty" jsonschema:"description:Filter by status"`
		Type    string `json:"type,omitempty" jsonschema:"description:Filter by type"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_rootcheck_database",
		Description: "Retrieve rootcheck database results for an agent (rootkit detection)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetRootcheckInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		items, err := client.GetRootcheckDatabase(in.AgentID, limit, in.Offset, in.Sort, in.Search, in.Status, in.Type)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Rootcheck Database:\n%s", prettyJSON(items))}},
		}, nil, nil
	})

	// get_rootcheck_last_scan
	type GetRootcheckLastScanInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Target agent ID"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_rootcheck_last_scan",
		Description: "Retrieve the last rootcheck scan time for an agent",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetRootcheckLastScanInput) (*mcp.CallToolResult, any, error) {
		result, err := client.GetRootcheckLastScan(in.AgentID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Rootcheck Last Scan:\n%s", prettyJSON(result))}},
		}, nil, nil
	})
}
