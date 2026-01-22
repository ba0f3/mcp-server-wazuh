package tools

import (
	"context"
	"fmt"
	"os"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerStatsTools registers statistics-related tools
func registerStatsTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_log_collector_stats
	type LogCollectorStatsInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Agent ID to get stats for (required)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_log_collector_stats",
		Description: "Retrieves log collector statistics for a specific Wazuh agent. Returns information about events processed, dropped, bytes, and target log files.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in LogCollectorStatsInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Log Collector Stats called with agent ID: %s\n", in.AgentID)
		agentID := formatAgentID(in.AgentID)

		stats, err := client.GetLogCollectorStats(agentID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving log collector stats: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: prettyJSON(stats)}},
		}, nil, nil
	})

	// get_wazuh_remoted_stats
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_remoted_stats",
		Description: "Retrieves statistics from the Wazuh remoted daemon. Returns information about queue size, TCP sessions, event counts, and message traffic.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Remoted Stats called\n")
		stats, err := client.GetRemotedStats()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving remoted stats: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: prettyJSON(stats)}},
		}, nil, nil
	})

	// get_wazuh_weekly_stats
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_weekly_stats",
		Description: "Retrieves weekly statistics from the Wazuh manager. Returns a JSON object detailing various metrics aggregated over the past week.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Weekly Stats called\n")
		stats, err := client.GetWeeklyStats()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving weekly stats: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: prettyJSON(stats)}},
		}, nil, nil
	})
}
