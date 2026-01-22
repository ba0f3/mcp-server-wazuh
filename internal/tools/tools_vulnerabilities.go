package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerVulnerabilityTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_vulnerabilities
	type GetVulnerabilitiesInput struct {
		AgentID  string `json:"agent_id,omitempty" jsonschema:"description:Filter by agent ID"`
		Severity string `json:"severity,omitempty" jsonschema:"description:Filter by severity (Critical, High, Medium, Low)"`
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_vulnerabilities",
		Description: "Retrieve a list of detected vulnerabilities with filtering options",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetVulnerabilitiesInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		vulns, err := client.GetVulnerabilities(in.AgentID, in.Severity, limit)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vulnerabilities:\n%s", prettyJSON(vulns))}},
		}, nil, nil
	})

	// get_wazuh_critical_vulnerabilities
	type LimitInput struct {
		Limit int `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 50)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_critical_vulnerabilities",
		Description: "Identify all vulnerabilities with 'Critical' severity requiring immediate action",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in LimitInput) (*mcp.CallToolResult, any, error) {
		limit := 50
		if in.Limit > 0 {
			limit = in.Limit
		}
		vulns, err := client.GetCriticalVulnerabilities(limit)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Critical Vulnerabilities:\n%s", prettyJSON(vulns))}},
		}, nil, nil
	})

	// get_wazuh_vulnerability_summary
	type VulnerabilitySummaryInput struct {
		TimeRange string `json:"time_range,omitempty" jsonschema:"description:Time range for summary (default: '7d')"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_vulnerability_summary",
		Description: "Get statistical summary of vulnerabilities across all agents or by time range",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in VulnerabilitySummaryInput) (*mcp.CallToolResult, any, error) {
		summary, err := client.GetVulnerabilitySummaryIndexer() // Reference uses indexer for this
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vulnerability Summary:\n%s", prettyJSON(summary))}},
		}, nil, nil
	})
}
