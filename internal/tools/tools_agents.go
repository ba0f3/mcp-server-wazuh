package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerAgentTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_agents
	type GetAgentsInput struct {
		Limit      int    `json:"limit,omitempty" jsonschema:"description:Maximum number of agents to retrieve (default: 100)"`
		Status     string `json:"status,omitempty" jsonschema:"description:Filter by status (active, disconnected, never_connected, pending)"`
		Name       string `json:"name,omitempty" jsonschema:"description:Filter by agent name"`
		IP         string `json:"ip,omitempty" jsonschema:"description:Filter by IP address"`
		Group      string `json:"group,omitempty" jsonschema:"description:Filter by group name"`
		OSPlatform string `json:"os_platform,omitempty" jsonschema:"description:Filter by OS platform"`
		Version    string `json:"version,omitempty" jsonschema:"description:Filter by agent version"`
		AgentID    string `json:"agent_id,omitempty" jsonschema:"description:Filter by specific agent ID (overrides other filters if used alone in API, but here we provide it for completeness)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_agents",
		Description: "Retrieve a list of all agents with their status and details",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetAgentsInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		var agents []wazuh.Agent
		var err error
		if in.AgentID != "" {
			var agent *wazuh.Agent
			agent, err = client.GetAgentInfo(in.AgentID)
			if err == nil {
				agents = []wazuh.Agent{*agent}
			}
		} else {
			agents, err = client.GetAgents(limit, in.Status, in.Name, in.IP, in.Group, in.OSPlatform, in.Version)
		}

		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(agents) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No agents found."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, agent := range agents {
			statusIndicator := "🔴"
			if agent.Status == "active" {
				statusIndicator = "🟢"
			} else if agent.Status == "pending" {
				statusIndicator = "🟡"
			}

			ipInfo := ""
			if agent.IP != "" {
				ipInfo = " (" + agent.IP + ")"
			}

			osInfo := ""
			if agent.OS.Name != "" {
				osInfo = "\nOS: " + agent.OS.Name
				if agent.OS.Version != "" {
					osInfo += " " + agent.OS.Version
				}
			}

			formattedText := fmt.Sprintf("%s Agent %s: %s%s%s\nVersion: %s", statusIndicator, agent.ID, agent.Name, ipInfo, osInfo, agent.Version)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}
		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// get_wazuh_running_agents
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_running_agents",
		Description: "Quickly retrieve all currently active/running security agents",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		agents, err := client.GetRunningAgents()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Running Agents:\n%s", prettyJSON(agents))}},
		}, nil, nil
	})

	// get_agent_daemon_stats - moved to stats tools, but keeping agent info here
	type AgentIDInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Target agent ID"`
	}

	// get_agent_processes
	type GetProcessesInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Target agent ID"`
		Limit   int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_processes",
		Description: "Retrieve a list of running processes on a specific agent (Syscollector)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetProcessesInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		processes, err := client.GetAgentProcesses(in.AgentID, limit)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Processes:\n%s", prettyJSON(processes))}},
		}, nil, nil
	})

	// get_agent_ports
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_ports",
		Description: "Retrieve a list of open network ports on a specific agent (Syscollector)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetProcessesInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		ports, err := client.GetAgentPorts(in.AgentID, limit)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Ports:\n%s", prettyJSON(ports))}},
		}, nil, nil
	})

	// get_agent_configuration
	type GetAgentConfigInput struct {
		AgentID      string `json:"agent_id" jsonschema:"description:Target agent ID"`
		Component    string `json:"component" jsonschema:"description:Configuration component (e.g., 'agent', 'wodle', 'syscollector')"`
		Configuration string `json:"configuration" jsonschema:"description:Configuration name (e.g., 'agent', 'wodle-syscollector')"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_configuration",
		Description: "Retrieve the active configuration of a specific agent component. Requires component and configuration parameters.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetAgentConfigInput) (*mcp.CallToolResult, any, error) {
		config, err := client.GetAgentConfiguration(in.AgentID, in.Component, in.Configuration)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Configuration:\n%s", prettyJSON(config))}},
		}, nil, nil
	})

	// get_agent_summary_os
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_summary_os",
		Description: "Retrieve a summary of agents grouped by operating system",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		summary, err := client.GetAgentSummaryOS()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent OS Summary:\n%s", prettyJSON(summary))}},
		}, nil, nil
	})

	// get_agent_summary_status
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_summary_status",
		Description: "Retrieve a summary of agents grouped by status (active, disconnected, etc.)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		summary, err := client.GetAgentSummaryStatus()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Status Summary:\n%s", prettyJSON(summary))}},
		}, nil, nil
	})

	// get_agent_groups
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_groups",
		Description: "Retrieve a list of all agent groups",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		groups, err := client.GetAgentGroups()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Groups:\n%s", prettyJSON(groups))}},
		}, nil, nil
	})

	// get_agent_distinct_stats
	type DistinctStatsInput struct {
		Field string `json:"field" jsonschema:"description:Field to get distinct values for (e.g., 'os.name', 'os.version', 'version')"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_agent_distinct_stats",
		Description: "Retrieve distinct statistics for a specific agent field",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in DistinctStatsInput) (*mcp.CallToolResult, any, error) {
		stats, err := client.GetAgentDistinctStats(in.Field)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Agent Distinct Statistics:\n%s", prettyJSON(stats))}},
		}, nil, nil
	})
}
