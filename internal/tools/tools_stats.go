package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerStatsTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_manager_daemon_stats
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_manager_daemon_stats",
		Description: "Retrieve comprehensive daemon statistics for the Wazuh manager (replaces deprecated /manager/stats/all endpoint)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		stats, err := client.GetManagerDaemonStats()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Manager Daemon Statistics:\n%s", prettyJSON(stats))}},
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

	// get_agent_daemon_stats
	type AgentDaemonStatsInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Target agent ID"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_daemon_stats",
		Description: "Retrieve daemon statistics for a specific agent",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AgentDaemonStatsInput) (*mcp.CallToolResult, any, error) {
		stats, err := client.GetAgentDaemonStats(in.AgentID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Daemon Statistics:\n%s", prettyJSON(stats))}},
		}, nil, nil
	})

	// get_agent_log_collector_stats
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_log_collector_stats",
		Description: "Retrieve log collector statistics for a specific agent",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AgentDaemonStatsInput) (*mcp.CallToolResult, any, error) {
		stats, err := client.GetLogCollectorStats(in.AgentID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Log Collector Statistics:\n%s", prettyJSON(stats))}},
		}, nil, nil
	})
}
