package tools

import (
	"context"
	"fmt"
	"os"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerAlertTools registers alert-related tools
func registerAlertTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_alert_summary
	type AlertSummaryInput struct {
		Limit int `json:"limit,omitempty" jsonschema:"description:Maximum number of alerts to retrieve (default: 300)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_alert_summary",
		Description: "Retrieves a summary of Wazuh security alerts. Returns formatted alert information including ID, timestamp, and description.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AlertSummaryInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Alert Summary called with limit: %d\n", in.Limit)
		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		alerts, err := client.GetAlerts(limit)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving alerts: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(alerts) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No Wazuh alerts found."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, alert := range alerts {
			source, ok := alert["_source"].(map[string]interface{})
			if !ok {
				source = alert
			}

			id := getString(source, "id")
			if id == "" {
				id = getString(alert, "_id")
			}
			if id == "" {
				id = "Unknown ID"
			}

			description := "No description available"
			if rule, ok := source["rule"].(map[string]interface{}); ok {
				description = getString(rule, "description")
			}

			timestamp := getString(source, "timestamp")
			if timestamp == "" {
				timestamp = "Unknown time"
			}

			agentName := "Unknown agent"
			if agent, ok := source["agent"].(map[string]interface{}); ok {
				agentName = getString(agent, "name")
			}

			ruleLevel := 0.0
			if rule, ok := source["rule"].(map[string]interface{}); ok {
				if l, ok := rule["level"].(float64); ok {
					ruleLevel = l
				}
			}

			srcIP := ""
			if data, ok := source["data"].(map[string]interface{}); ok {
				srcIP = getString(data, "srcip")
				if srcIP == "" {
					srcIP = getString(data, "src_ip")
				}
			}

			dstIP := ""
			if data, ok := source["data"].(map[string]interface{}); ok {
				dstIP = getString(data, "dstip")
				if dstIP == "" {
					dstIP = getString(data, "dst_ip")
				}
			}

			srcUser := ""
			if data, ok := source["data"].(map[string]interface{}); ok {
				srcUser = getString(data, "srcuser")
				if srcUser == "" {
					srcUser = getString(data, "dstuser")
				}
			}

			formattedText := fmt.Sprintf("Alert ID: %s\nTime: %s\nAgent: %s\nLevel: %.0f\nDescription: %s", id, timestamp, agentName, ruleLevel, description)
			if srcIP != "" {
				formattedText += fmt.Sprintf("\nSource IP: %s", srcIP)
			}
			if dstIP != "" {
				formattedText += fmt.Sprintf("\nDestination IP: %s", dstIP)
			}
			if srcUser != "" {
				formattedText += fmt.Sprintf("\nUser: %s", srcUser)
			}

			items = append(items, &mcp.TextContent{Text: formattedText})
		}
		return &mcp.CallToolResult{Content: items}, nil, nil
	})
}
