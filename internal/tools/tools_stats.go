package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerStatsTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_statistics
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_statistics",
		Description: "Retrieve comprehensive performance and operational statistics of the Wazuh manager",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		stats, err := client.GetWazuhStatistics()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Wazuh Statistics:\n%s", prettyJSON(stats))}},
		}, nil, nil
	})

	// get_wazuh_weekly_stats
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_weekly_stats",
		Description: "Retrieve historical security statistics aggregated over the past week",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		stats, err := client.GetWeeklyStats()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Weekly Statistics:\n%s", prettyJSON(stats))}},
		}, nil, nil
	})

	// get_wazuh_remoted_stats
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_remoted_stats",
		Description: "Retrieve statistics for the remoted service (agent connections and data throughput)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		stats, err := client.GetRemotedStats()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Remoted Statistics:\n%s", prettyJSON(stats))}},
		}, nil, nil
	})

	// get_wazuh_log_collector_stats
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_log_collector_stats",
		Description: "Retrieve statistics for the log collector service",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		// In reference project this seems to be for manager, but current implementation takes agentID.
		// Let's use it for manager (empty agentID if supported by API or just use what we have)
		stats, err := client.GetLogCollectorStats("")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Log Collector Statistics:\n%s", prettyJSON(stats))}},
		}, nil, nil
	})
}
