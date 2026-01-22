package tools

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerAgentTools registers agent-related tools
func registerAgentTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_agents
	type AgentsInput struct {
		Limit      int    `json:"limit,omitempty" jsonschema:"description:Maximum number of agents to retrieve (default: 300)"`
		Status     string `json:"status,omitempty" jsonschema:"description:Agent status filter (active, disconnected, pending, never_connected)"`
		Name       string `json:"name,omitempty" jsonschema:"description:Agent name to search for (optional)"`
		IP         string `json:"ip,omitempty" jsonschema:"description:Agent IP address to filter by (optional)"`
		Group      string `json:"group,omitempty" jsonschema:"description:Agent group to filter by (optional)"`
		OSPlatform string `json:"os_platform,omitempty" jsonschema:"description:Operating system platform to filter by (optional)"`
		Version    string `json:"version,omitempty" jsonschema:"description:Agent version to filter by (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_agents",
		Description: "Retrieves a list of Wazuh agents with their current status and details. Returns formatted agent information including ID, name, IP, status, OS details, and last activity. Supports filtering by status, name, IP, group, OS platform, and version.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AgentsInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Agents called with limit: %d, status: %s, name: %s, IP: %s, group: %s, OS platform: %s, version: %s\n", in.Limit, in.Status, in.Name, in.IP, in.Group, in.OSPlatform, in.Version)
		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		agents, err := client.GetAgents(limit, in.Status, in.Name, in.IP, in.Group, in.OSPlatform, in.Version)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving agents: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(agents) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No Wazuh agents found matching the specified criteria."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, agent := range agents {
			statusIndicator := agent.Status
			switch strings.ToLower(agent.Status) {
			case "active":
				statusIndicator = "🟢 ACTIVE"
			case "disconnected":
				statusIndicator = "🔴 DISCONNECTED"
			case "pending":
				statusIndicator = "🟡 PENDING"
			case "never_connected":
				statusIndicator = "⚪ NEVER CONNECTED"
			}

			ipInfo := ""
			if agent.IP != "" {
				ipInfo = "\nIP: " + agent.IP
			}

			registerIPInfo := ""
			if agent.RegisterIP != "" && agent.RegisterIP != agent.IP {
				registerIPInfo = "\nRegistered IP: " + agent.RegisterIP
			}

			osInfo := ""
			if agent.OS.Name != "" {
				osParts := []string{agent.OS.Name}
				if agent.OS.Version != "" {
					osParts = append(osParts, agent.OS.Version)
				}
				if agent.OS.Arch != "" {
					osParts = append(osParts, "("+agent.OS.Arch+")")
				}
				osInfo = "\nOS: " + strings.Join(osParts, " ")
			}

			versionInfo := ""
			if agent.Version != "" {
				versionInfo = "\nAgent Version: " + agent.Version
			}

			groupInfo := ""
			if len(agent.Group) > 0 {
				groupInfo = "\nGroups: " + strings.Join(agent.Group, ", ")
			}

			lastKeepAliveInfo := ""
			if agent.LastKeepAlive != "" {
				lastKeepAliveInfo = "\nLast Keep Alive: " + agent.LastKeepAlive
			}

			dateAddInfo := ""
			if agent.DateAdd != "" {
				dateAddInfo = "\nRegistered: " + agent.DateAdd
			}

			nodeInfo := ""
			if agent.NodeName != "" {
				nodeInfo = "\nNode: " + agent.NodeName
			}

			configStatusInfo := ""
			if agent.GroupConfigStatus != "" {
				configIndicator := agent.GroupConfigStatus
				switch strings.ToLower(agent.GroupConfigStatus) {
				case "synced":
					configIndicator = "✅ SYNCED"
				case "not synced":
					configIndicator = "❌ NOT SYNCED"
				}
				configStatusInfo = "\nConfig Status: " + configIndicator
			}

			agentIDDisplay := agent.ID
			if agent.ID == "000" {
				agentIDDisplay = "000 (Wazuh Manager)"
			}

			formattedText := fmt.Sprintf("Agent ID: %s\nName: %s\nStatus: %s%s%s%s%s%s%s%s%s%s",
				agentIDDisplay, agent.Name, statusIndicator, ipInfo, registerIPInfo, osInfo, versionInfo, groupInfo, lastKeepAliveInfo, dateAddInfo, nodeInfo, configStatusInfo)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// get_wazuh_agent_processes
	type AgentProcessesInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Agent ID to get processes for (required)"`
		Limit   int    `json:"limit,omitempty" jsonschema:"description:Maximum number of processes to retrieve (default: 300)"`
		Search  string `json:"search,omitempty" jsonschema:"description:Search string to filter processes by name or command (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_agent_processes",
		Description: "Retrieves a list of running processes for a specific Wazuh agent. Returns formatted process information including PID, name, state, user, and command. Supports filtering by process name/command.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AgentProcessesInput) (*mcp.CallToolResult, any, error) {
		agentID := formatAgentID(in.AgentID)

		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		processes, err := client.GetAgentProcesses(agentID, limit, in.Search)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving processes: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(processes) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("No processes found for agent %s matching the specified criteria.", agentID)}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, proc := range processes {
			var details []string
			details = append(details, fmt.Sprintf("PID: %d", proc.PID))
			details = append(details, fmt.Sprintf("Name: %s", proc.Name))
			if proc.State != "" {
				details = append(details, fmt.Sprintf("State: %s", proc.State))
			}
			if proc.PPID != 0 {
				details = append(details, fmt.Sprintf("PPID: %d", proc.PPID))
			}
			if proc.EUser != "" {
				details = append(details, fmt.Sprintf("User: %s", proc.EUser))
			}
			if proc.Cmd != "" {
				details = append(details, fmt.Sprintf("Command: %s", proc.Cmd))
			}
			if proc.StartTime != "" {
				details = append(details, fmt.Sprintf("Start Time: %s", proc.StartTime))
			}
			if proc.Resident > 0 {
				details = append(details, fmt.Sprintf("Memory (Resident): %d KB", proc.Resident/1024))
			}
			if proc.VMSize > 0 {
				details = append(details, fmt.Sprintf("Memory (VM Size): %d KB", proc.VMSize/1024))
			}

			items = append(items, &mcp.TextContent{Text: strings.Join(details, "\n")})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// get_wazuh_agent_ports
	type AgentPortsInput struct {
		AgentID  string `json:"agent_id" jsonschema:"description:Agent ID to get network ports for (required)"`
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum number of ports to retrieve (default: 300)"`
		Protocol string `json:"protocol,omitempty" jsonschema:"description:Protocol to filter by (e.g., \"tcp\", \"udp\")"`
		State    string `json:"state,omitempty" jsonschema:"description:State to filter by (e.g., \"LISTENING\", \"ESTABLISHED\")"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_agent_ports",
		Description: "Retrieves a list of open network ports for a specific Wazuh agent. Returns formatted port information including local/remote IP and port, protocol, state, and associated process/PID. Supports filtering by protocol and state.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AgentPortsInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Agent Ports called with agent ID: %s, limit: %d, protocol: %s, state: %s\n", in.AgentID, in.Limit, in.Protocol, in.State)
		agentID := formatAgentID(in.AgentID)

		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		// Fetch more to allow for client-side state filtering
		ports, err := client.GetAgentPorts(agentID, limit*2, in.Protocol)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving agent ports: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if in.State != "" {
			var filtered []wazuh.Port
			isListening := strings.EqualFold(in.State, "listening")
			for _, port := range ports {
				match := false
				if port.State != "" {
					if isListening {
						match = strings.EqualFold(port.State, "listening")
					} else {
						match = !strings.EqualFold(port.State, "listening")
					}
				} else {
					match = !isListening
				}
				if match {
					filtered = append(filtered, port)
				}
			}
			ports = filtered
		}

		if len(ports) > limit {
			ports = ports[:limit]
		}

		if len(ports) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("No network ports found for agent %s matching the specified criteria.", agentID)}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, port := range ports {
			details := []string{
				fmt.Sprintf("Protocol: %s", port.Protocol),
				fmt.Sprintf("Local: %s:%d", port.Local.IP, port.Local.Port),
			}
			if port.Remote.IP != "" || port.Remote.Port != 0 {
				details = append(details, fmt.Sprintf("Remote: %s:%d", port.Remote.IP, port.Remote.Port))
			}
			if port.State != "" {
				details = append(details, fmt.Sprintf("State: %s", port.State))
			}
			if port.Process != "" {
				details = append(details, fmt.Sprintf("Process Name: %s", port.Process))
			}
			if port.PID != 0 {
				details = append(details, fmt.Sprintf("PID: %d", port.PID))
			}
			if port.Inode != 0 {
				details = append(details, fmt.Sprintf("Inode: %d", port.Inode))
			}

			items = append(items, &mcp.TextContent{Text: strings.Join(details, "\n")})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})
}
