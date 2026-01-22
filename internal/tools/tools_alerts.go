package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerAlertTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_alerts
	type GetAlertsInput struct {
		Limit          int    `json:"limit,omitempty" jsonschema:"description:Maximum number of results (default: 100),minimum:1,maximum:1000"`
		RuleID         string `json:"rule_id,omitempty" jsonschema:"description:Filter by specific rule ID"`
		Level          string `json:"level,omitempty" jsonschema:"description:Filter by alert level (e.g., '12', '10+')"`
		AgentID        string `json:"agent_id,omitempty" jsonschema:"description:Filter by agent ID"`
		TimestampStart string `json:"timestamp_start,omitempty" jsonschema:"description:Start timestamp (ISO format)"`
		TimestampEnd   string `json:"timestamp_end,omitempty" jsonschema:"description:End timestamp (ISO format)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_alerts",
		Description: "Retrieve Wazuh security alerts with optional filtering",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetAlertsInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		alerts, err := client.GetAlerts(limit, in.RuleID, in.Level, in.AgentID, in.TimestampStart, in.TimestampEnd)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
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
			ruleLevel := 0.0
			if rule, ok := source["rule"].(map[string]interface{}); ok {
				description = getString(rule, "description")
				if l, ok := rule["level"].(float64); ok {
					ruleLevel = l
				}
			}

			timestamp := getString(source, "timestamp")
			agentName := "Unknown agent"
			if agent, ok := source["agent"].(map[string]interface{}); ok {
				agentName = getString(agent, "name")
			}

			formattedText := fmt.Sprintf("Alert ID: %s\nTime: %s\nAgent: %s\nLevel: %.0f\nDescription: %s", id, timestamp, agentName, ruleLevel, description)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}
		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// get_wazuh_alert_summary
	type AlertSummaryInput struct {
		TimeRange string `json:"time_range,omitempty" jsonschema:"description:Time range (e.g., '24h', '7d')"`
		GroupBy   string `json:"group_by,omitempty" jsonschema:"description:Field to group by (default: 'rule.level')"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_alert_summary",
		Description: "Retrieve a summary of security alerts grouped by specific fields",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AlertSummaryInput) (*mcp.CallToolResult, any, error) {
		summary, err := client.GetAlertSummary(in.TimeRange, in.GroupBy)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving alerts: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Alert Summary:\n%s", prettyJSON(summary))}},
		}, nil, nil
	})

	// analyze_alert_patterns
	type AnalyzePatternsInput struct {
		TimeRange    string `json:"time_range,omitempty" jsonschema:"description:Time range to analyze (default: '24h')"`
		MinFrequency int    `json:"min_frequency,omitempty" jsonschema:"description:Minimum occurrence to consider a pattern (default: 5)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "analyze_alert_patterns",
		Description: "Analyze security alerts to identify recurring attack patterns or trends",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AnalyzePatternsInput) (*mcp.CallToolResult, any, error) {
		minFreq := 5
		if in.MinFrequency > 0 {
			minFreq = in.MinFrequency
		}
		patterns, err := client.AnalyzeAlertPatterns(in.TimeRange, minFreq)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Alert Patterns:\n%s", prettyJSON(patterns))}},
		}, nil, nil
	})

	// search_security_events
	type SearchEventsInput struct {
		Query     string `json:"query" jsonschema:"description:Search query in Wazuh format"`
		TimeRange string `json:"time_range,omitempty" jsonschema:"description:Time range (default: '24h')"`
		Limit     int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_security_events",
		Description: "Perform advanced search across all security events and logs",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in SearchEventsInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		events, err := client.SearchSecurityEvents(in.Query, in.TimeRange, limit)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Security Events:\n%s", prettyJSON(events))}},
		}, nil, nil
	})
}
