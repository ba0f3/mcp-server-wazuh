package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerRulesTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_rules_summary
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_rules_summary",
		Description: "Retrieve a statistical summary of all active security rules",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		summary, err := client.GetRulesSummary()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Rules Summary:\n%s", prettyJSON(summary))}},
		}, nil, nil
	})
}
