package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerSCATools(s *mcp.Server, client *wazuh.Client) {
	// get_sca_policies
	type GetSCAPoliciesInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Target agent ID"`
		Limit   int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset  int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sca_policies",
		Description: "Retrieve Security Configuration Assessment (SCA) policies for an agent",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetSCAPoliciesInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		policies, err := client.GetSCAPolicies(in.AgentID, limit, in.Offset)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("SCA Policies:\n%s", prettyJSON(policies))}},
		}, nil, nil
	})

	// get_sca_policy_checks
	type GetSCAChecksInput struct {
		AgentID  string `json:"agent_id" jsonschema:"description:Target agent ID"`
		PolicyID string `json:"policy_id" jsonschema:"description:SCA policy ID"`
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset   int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sca_policy_checks",
		Description: "Retrieve checks for a specific SCA policy on an agent",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetSCAChecksInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		checks, err := client.GetSCAPolicyChecks(in.AgentID, in.PolicyID, limit, in.Offset)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("SCA Policy Checks:\n%s", prettyJSON(checks))}},
		}, nil, nil
	})

	// get_sca_summary
	type GetSCASummaryInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Target agent ID"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_sca_summary",
		Description: "Retrieve a summary of SCA results for an agent",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetSCASummaryInput) (*mcp.CallToolResult, any, error) {
		summary, err := client.GetSCASummary(in.AgentID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("SCA Summary:\n%s", prettyJSON(summary))}},
		}, nil, nil
	})
}
