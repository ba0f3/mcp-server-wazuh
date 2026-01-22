package tools

import (
	"context"
	"fmt"
	"os"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerLogTools registers log-related tools
func registerLogTools(s *mcp.Server, client *wazuh.Client) {
	// search_wazuh_manager_logs
	type SearchManagerLogsInput struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum number of logs to retrieve (default: 300)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Level  string `json:"level,omitempty" jsonschema:"description:Log level to filter by (optional)"`
		Tag    string `json:"tag,omitempty" jsonschema:"description:Log tag to filter by (optional)"`
		Search string `json:"search,omitempty" jsonschema:"description:Search string to filter logs (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_wazuh_manager_logs",
		Description: "Searches Wazuh manager logs. Returns formatted log entries including timestamp, tag, level, and description. Supports filtering by limit, offset, level, tag, and a search term.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in SearchManagerLogsInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Search Wazuh Manager Logs called with limit: %d, offset: %d, level: %s, tag: %s, search: %s\n", in.Limit, in.Offset, in.Level, in.Tag, in.Search)
		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		logs, err := client.GetManagerLogs(limit, in.Offset, in.Level, in.Tag, in.Search)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving manager logs: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(logs) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No manager logs found matching the specified criteria."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, log := range logs {
			formattedText := fmt.Sprintf("Timestamp: %s\nTag: %s\nLevel: %s\nDescription: %s",
				log.Timestamp, log.Tag, log.Level, log.Description)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// get_wazuh_manager_error_logs
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_manager_error_logs",
		Description: "Retrieves Wazuh manager error logs. Returns formatted log entries including timestamp, tag, level (error), and description.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Manager Error Logs called\n")
		logs, err := client.GetManagerLogs(300, 0, "error", "", "")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving manager error logs: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(logs) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No manager error logs found."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, log := range logs {
			formattedText := fmt.Sprintf("Timestamp: %s\nTag: %s\nLevel: %s\nDescription: %s",
				log.Timestamp, log.Tag, log.Level, log.Description)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})
}
