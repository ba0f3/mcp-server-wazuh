package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerMITRETools(s *mcp.Server, client *wazuh.Client) {
	// get_mitre_techniques
	type GetMITRETechniquesInput struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Query  string `json:"query,omitempty" jsonschema:"description:Query string"`
		Select string `json:"select,omitempty" jsonschema:"description:Select fields"`
		Sort   string `json:"sort,omitempty" jsonschema:"description:Sort field"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_mitre_techniques",
		Description: "Retrieve MITRE ATT&CK techniques",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetMITRETechniquesInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		techniques, err := client.GetMITRETechniques(limit, in.Offset, in.Query, in.Select, in.Sort)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("MITRE Techniques:\n%s", prettyJSON(techniques))}},
		}, nil, nil
	})

	// get_mitre_technique_by_id
	type GetMITRETechniqueInput struct {
		TechniqueID string `json:"technique_id" jsonschema:"description:MITRE technique ID (e.g., T1005)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_mitre_technique_by_id",
		Description: "Retrieve a specific MITRE ATT&CK technique by ID",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetMITRETechniqueInput) (*mcp.CallToolResult, any, error) {
		technique, err := client.GetMITRETechniqueByID(in.TechniqueID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("MITRE Technique:\n%s", prettyJSON(technique))}},
		}, nil, nil
	})

	// get_mitre_agents
	type GetMITREAgentsInput struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Query  string `json:"query,omitempty" jsonschema:"description:Query string"`
		Select string `json:"select,omitempty" jsonschema:"description:Select fields"`
		Sort   string `json:"sort,omitempty" jsonschema:"description:Sort field"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_mitre_agents",
		Description: "Retrieve agents with MITRE ATT&CK techniques",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetMITREAgentsInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		result, err := client.GetMITREAgents(limit, in.Offset, in.Query, in.Select, in.Sort)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("MITRE Agents:\n%s", prettyJSON(result))}},
		}, nil, nil
	})
}
