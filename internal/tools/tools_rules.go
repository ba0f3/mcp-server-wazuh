package tools

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerRulesTools registers rules-related tools
func registerRulesTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_rules_summary
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
}
