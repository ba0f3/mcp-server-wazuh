package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/joho/godotenv"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	_ = godotenv.Load()

	apiHost := getEnv("WAZUH_API_HOST", "localhost")
	apiPort, _ := strconv.Atoi(getEnv("WAZUH_API_PORT", "55000"))
	apiUsername := getEnv("WAZUH_API_USERNAME", "wazuh")
	apiPassword := getEnv("WAZUH_API_PASSWORD", "wazuh")

	indexerHost := getEnv("WAZUH_INDEXER_HOST", "localhost")
	indexerPort, _ := strconv.Atoi(getEnv("WAZUH_INDEXER_PORT", "9200"))
	indexerUsername := getEnv("WAZUH_INDEXER_USERNAME", "admin")
	indexerPassword := getEnv("WAZUH_INDEXER_PASSWORD", "admin")

	verifySSL := getEnv("WAZUH_VERIFY_SSL", "false") == "true"

	transport := getEnv("MCP_SERVER_TRANSPORT", "stdio")

	host := getEnv("MCP_SERVER_HOST", "localhost")
	port, _ := strconv.Atoi(getEnv("MCP_SERVER_PORT", "8000"))

	client := wazuh.NewClient(apiHost, apiPort, apiUsername, apiPassword, indexerHost, indexerPort, indexerUsername, indexerPassword, verifySSL)
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-server-wazuh", Version: "0.3.0"}, nil)

	registerTools(s, client)

	if transport == "http" {
		// Create the streamable HTTP handler.
		handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
			return s
		}, nil)

		url := fmt.Sprintf("%s:%d", host, port)

		fmt.Fprintf(os.Stderr, "MCP server listening on %s\n", url)

		// Start the HTTP server.
		if err := http.ListenAndServe(url, handler); err != nil {
			fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func registerTools(s *mcp.Server, client *wazuh.Client) {
	// 1. get_wazuh_alert_summary
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

	// 2. get_wazuh_rules_summary
	type RulesSummaryInput struct {
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum number of rules to retrieve (default: 300)"`
		Level    uint32 `json:"level,omitempty" jsonschema:"description:Rule level to filter by (optional)"`
		Group    string `json:"group,omitempty" jsonschema:"description:Rule group to filter by (optional)"`
		Filename string `json:"filename,omitempty" jsonschema:"description:Filename to filter by (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_rules_summary",
		Description: "Retrieves a summary of Wazuh security rules. Returns formatted rule information including ID, level, description, and groups. Supports filtering by level, group, and filename.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in RulesSummaryInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Rules Summary called with limit: %d, level: %d, group: %s, filename: %s\n", in.Limit, in.Level, in.Group, in.Filename)
		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		var level *uint32
		if in.Level > 0 {
			level = &in.Level
		}

		rules, err := client.GetRules(limit, level, in.Group, in.Filename)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving rules: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(rules) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No Wazuh rules found matching the specified criteria."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, rule := range rules {
			groupsStr := strings.Join(rule.Groups, ", ")
			severity := "Unknown"
			switch {
			case rule.Level <= 3:
				severity = "Low"
			case rule.Level <= 7:
				severity = "Medium"
			case rule.Level <= 12:
				severity = "High"
			case rule.Level <= 15:
				severity = "Critical"
			}

			complianceInfo := ""
			var compliance []string
			if len(rule.GDPR) > 0 {
				compliance = append(compliance, "GDPR: "+strings.Join(rule.GDPR, ", "))
			}
			if len(rule.HIPAA) > 0 {
				compliance = append(compliance, "HIPAA: "+strings.Join(rule.HIPAA, ", "))
			}
			if len(rule.PCIDSS) > 0 {
				compliance = append(compliance, "PCI DSS: "+strings.Join(rule.PCIDSS, ", "))
			}
			if len(rule.NIST800_53) > 0 {
				compliance = append(compliance, "NIST 800-53: "+strings.Join(rule.NIST800_53, ", "))
			}
			if len(compliance) > 0 {
				complianceInfo = "\nCompliance: " + strings.Join(compliance, " | ")
			}

			formattedText := fmt.Sprintf("Rule ID: %d\nLevel: %d (%s)\nDescription: %s\nGroups: %s\nFile: %s\nStatus: %s%s",
				rule.ID, rule.Level, severity, rule.Description, groupsStr, rule.Filename, rule.Status, complianceInfo)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// 3. get_wazuh_vulnerability_summary
	type VulnerabilitySummaryInput struct {
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum number of vulnerabilities to retrieve (default: 10000)"`
		AgentID  string `json:"agent_id" jsonschema:"description:Agent ID to filter vulnerabilities by (required)"`
		Severity string `json:"severity,omitempty" jsonschema:"description:Severity level to filter by (Low, Medium, High, Critical) (optional)"`
		CVE      string `json:"cve,omitempty" jsonschema:"description:CVE ID to search for (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_vulnerability_summary",
		Description: "Retrieves a summary of Wazuh vulnerability detections for a specific agent. Returns formatted vulnerability information including CVE ID, severity, detection time, and agent details. Supports filtering by severity level.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in VulnerabilitySummaryInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Vulnerability Summary called with agent ID: %s, limit: %d, severity: %s, CVE: %s\n", in.AgentID, in.Limit, in.Severity, in.CVE)
		agentID := formatAgentID(in.AgentID)

		limit := 10000
		if in.Limit > 0 {
			limit = in.Limit
		}

		vulns, err := client.GetAgentVulnerabilities(agentID, limit, in.Severity)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving vulnerabilities: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(vulns) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No Wazuh vulnerabilities found matching the specified criteria."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, vuln := range vulns {
			severityIndicator := vuln.Severity
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				severityIndicator = "🔴 CRITICAL"
			case "HIGH":
				severityIndicator = "🟠 HIGH"
			case "MEDIUM":
				severityIndicator = "🟡 MEDIUM"
			case "LOW":
				severityIndicator = "🟢 LOW"
			}

			agentInfo := ""
			if vuln.AgentID != "" {
				if vuln.AgentID == "000" {
					agentInfo = fmt.Sprintf("\nAgent: %s (Wazuh Manager, ID: 000)", vuln.AgentName)
				} else {
					agentInfo = fmt.Sprintf("\nAgent: %s (ID: %s)", vuln.AgentName, vuln.AgentID)
				}
			}

			cvssInfo := ""
			if vuln.CVSS != nil {
				var cvssParts []string
				if vuln.CVSS.CVSS2 != nil && vuln.CVSS.CVSS2.BaseScore > 0 {
					cvssParts = append(cvssParts, fmt.Sprintf("CVSS2: %.1f", vuln.CVSS.CVSS2.BaseScore))
				}
				if vuln.CVSS.CVSS3 != nil && vuln.CVSS.CVSS3.BaseScore > 0 {
					cvssParts = append(cvssParts, fmt.Sprintf("CVSS3: %.1f", vuln.CVSS.CVSS3.BaseScore))
				}
				if len(cvssParts) > 0 {
					cvssInfo = "\nCVSS Scores: " + strings.Join(cvssParts, ", ")
				}
			}

			description := vuln.Description
			if description == "" {
				description = "No description available"
			}

			formattedText := fmt.Sprintf("CVE: %s\nSeverity: %s\nTitle: %s\nDescription: %s",
				vuln.CVE, severityIndicator, vuln.Title, description)
			if vuln.Published != "" {
				formattedText += "\nPublished: " + vuln.Published
			}
			if vuln.Updated != "" {
				formattedText += "\nUpdated: " + vuln.Updated
			}
			if vuln.DetectionTime != "" {
				formattedText += "\nDetection Time: " + vuln.DetectionTime
			}
			formattedText += agentInfo + cvssInfo
			if vuln.Reference != "" {
				formattedText += "\nReference: " + vuln.Reference
			}

			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// 4. get_wazuh_critical_vulnerabilities
	type CriticalVulnerabilitiesInput struct {
		AgentID string `json:"agent_id" jsonschema:"description:Agent ID to get critical vulnerabilities for (required)"`
		Limit   int    `json:"limit,omitempty" jsonschema:"description:Maximum number of vulnerabilities to retrieve (default: 300)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_critical_vulnerabilities",
		Description: "Retrieves critical vulnerabilities for a specific Wazuh agent. Returns formatted vulnerability information including CVE ID, title, description, CVSS scores, and detection details. Only shows vulnerabilities with 'Critical' severity level.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in CriticalVulnerabilitiesInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Critical Vulnerabilities called with agent ID: %s, limit: %d\n", in.AgentID, in.Limit)
		agentID := formatAgentID(in.AgentID)

		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		vulns, err := client.GetAgentVulnerabilities(agentID, limit, "Critical")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving critical vulnerabilities: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(vulns) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("No critical vulnerabilities found for agent %s.", agentID)}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, vuln := range vulns {
			agentInfo := ""
			if vuln.AgentID != "" {
				agentInfo = fmt.Sprintf("\nAgent: %s (ID: %s)", vuln.AgentName, vuln.AgentID)
			}

			cvssInfo := ""
			if vuln.CVSS != nil {
				var cvssParts []string
				if vuln.CVSS.CVSS2 != nil && vuln.CVSS.CVSS2.BaseScore > 0 {
					cvssParts = append(cvssParts, fmt.Sprintf("CVSS2: %.1f", vuln.CVSS.CVSS2.BaseScore))
				}
				if vuln.CVSS.CVSS3 != nil && vuln.CVSS.CVSS3.BaseScore > 0 {
					cvssParts = append(cvssParts, fmt.Sprintf("CVSS3: %.1f", vuln.CVSS.CVSS3.BaseScore))
				}
				if len(cvssParts) > 0 {
					cvssInfo = "\nCVSS Scores: " + strings.Join(cvssParts, ", ")
				}
			}

			description := vuln.Description
			if description == "" {
				description = "No description available"
			}

			formattedText := fmt.Sprintf("🔴 CRITICAL VULNERABILITY\nCVE: %s\nTitle: %s\nDescription: %s",
				vuln.CVE, vuln.Title, description)
			if vuln.Published != "" {
				formattedText += "\nPublished: " + vuln.Published
			}
			if vuln.Updated != "" {
				formattedText += "\nUpdated: " + vuln.Updated
			}
			if vuln.DetectionTime != "" {
				formattedText += "\nDetection Time: " + vuln.DetectionTime
			}
			formattedText += agentInfo + cvssInfo
			if vuln.Reference != "" {
				formattedText += "\nReference: " + vuln.Reference
			}

			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// 5. get_wazuh_agents
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

	// 6. get_wazuh_agent_processes
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

	// 7. get_wazuh_cluster_health
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_cluster_health",
		Description: "Checks the health of the Wazuh cluster. Returns whether the cluster is enabled, running, and if nodes are connected.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		health, err := client.GetClusterHealth()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving cluster health: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		formattedText := fmt.Sprintf("Cluster Enabled: %s\nCluster Running: %s", health.Enabled, health.Running)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: formattedText}},
		}, nil, nil
	})

	// 8. get_wazuh_cluster_nodes
	type ClusterNodesInput struct {
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum number of nodes to retrieve (default: 300)"`
		Offset   int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		NodeType string `json:"node_type,omitempty" jsonschema:"description:Node type to filter by (worker, master) (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_cluster_nodes",
		Description: "Retrieves a list of nodes in the Wazuh cluster. Returns formatted node information including name, type, version, IP, and status. Supports filtering by limit, offset, and node type.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in ClusterNodesInput) (*mcp.CallToolResult, any, error) {
		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		nodes, err := client.GetClusterNodes(limit, in.Offset, in.NodeType)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving cluster nodes: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(nodes) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No cluster nodes found matching the specified criteria."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, node := range nodes {
			formattedText := fmt.Sprintf("Node Name: %s\nType: %s\nVersion: %s\nIP: %s\nStatus: %s",
				node.Name, node.Type, node.Version, node.IP, node.Status)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// 9. search_wazuh_manager_logs
	type SearchManagerLogsInput struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum number of logs to retrieve (default: 300)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Level  string `json:"level,omitempty" jsonschema:"description:Log level to filter by (optional)"`
		Tag    string `json:"tag,omitempty" jsonschema:"description:Log tag to filter by (optional)"`
		Search string `json:"search,omitempty" jsonschema:"description:Search string to filter logs (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_wazuh_manager_logs",
		Description: "Searches Wazuh manager logs. Returns formatted log entries including timestamp, tag, level, and description. Supports filtering by limit, offset, level, tag, and a search term.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in SearchManagerLogsInput) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Search Wazuh Manager Logs called with limit: %d, offset: %d, level: %s, tag: %s, search: %s\n", in.Limit, in.Offset, in.Level, in.Tag, in.Search)
		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		logs, err := client.GetManagerLogs(limit, in.Offset, in.Level, in.Tag, in.Search)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving manager logs: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(logs) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No manager logs found matching the specified criteria."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, log := range logs {
			formattedText := fmt.Sprintf("Timestamp: %s\nTag: %s\nLevel: %s\nDescription: %s",
				log.Timestamp, log.Tag, log.Level, log.Description)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// 10. get_wazuh_manager_error_logs
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_manager_error_logs",
		Description: "Retrieves Wazuh manager error logs. Returns formatted log entries including timestamp, tag, level (error), and description.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		fmt.Fprintf(os.Stderr, "Get Wazuh Manager Error Logs called\n")
		logs, err := client.GetManagerLogs(300, 0, "error", "", "")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving manager error logs: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(logs) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No manager error logs found."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, log := range logs {
			formattedText := fmt.Sprintf("Timestamp: %s\nTag: %s\nLevel: %s\nDescription: %s",
				log.Timestamp, log.Tag, log.Level, log.Description)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})

	// 11. get_wazuh_log_collector_stats
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

	// 12. get_wazuh_remoted_stats
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

	// 13. get_wazuh_agent_ports
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

	// 14. get_wazuh_weekly_stats
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

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func prettyJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func formatAgentID(id string) string {
	if n, err := strconv.Atoi(id); err == nil {
		if n <= 999 {
			return fmt.Sprintf("%03d", n)
		}
	}
	return id
}
