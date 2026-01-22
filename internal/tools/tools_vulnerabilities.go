package tools

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerVulnerabilityTools registers vulnerability-related tools
func registerVulnerabilityTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_vulnerability_summary
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

	// get_wazuh_critical_vulnerabilities
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
}
