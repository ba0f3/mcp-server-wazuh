package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerSecurityTools(s *mcp.Server, client *wazuh.Client) {
	// analyze_security_threat
	type AnalyzeThreatInput struct {
		Indicator     string `json:"indicator" jsonschema:"description:Threat indicator (IP, hash, domain, etc.)"`
		IndicatorType string `json:"indicator_type" jsonschema:"description:Type of indicator (e.g., 'ip', 'hash', 'domain')"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "analyze_security_threat",
		Description: "Analyze a specific security threat indicator to determine its risk and origin",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AnalyzeThreatInput) (*mcp.CallToolResult, any, error) {
		result, err := client.AnalyzeSecurityThreat(in.Indicator, in.IndicatorType)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Threat Analysis:\n%s", prettyJSON(result))}},
		}, nil, nil
	})

	// check_ioc_reputation
	mcp.AddTool(s, &mcp.Tool{
		Name:        "check_ioc_reputation",
		Description: "Check the global reputation of an Indicator of Compromise (IoC)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in AnalyzeThreatInput) (*mcp.CallToolResult, any, error) {
		result, err := client.CheckIOCReputation(in.Indicator, in.IndicatorType)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("IoC Reputation:\n%s", prettyJSON(result))}},
		}, nil, nil
	})

	// perform_risk_assessment
	type RiskAssessmentInput struct {
		AgentID string `json:"agent_id,omitempty" jsonschema:"description:Optional agent ID to assess"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "perform_risk_assessment",
		Description: "Perform a comprehensive security risk assessment for the entire environment or a specific agent",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in RiskAssessmentInput) (*mcp.CallToolResult, any, error) {
		result, err := client.PerformRiskAssessment(in.AgentID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Risk Assessment:\n%s", prettyJSON(result))}},
		}, nil, nil
	})

	// get_top_security_threats
	type TopThreatsInput struct {
		Limit     int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 10)"`
		TimeRange string `json:"time_range,omitempty" jsonschema:"description:Time range (default: '24h')"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_top_security_threats",
		Description: "Identify the top security threats currently active in the environment",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in TopThreatsInput) (*mcp.CallToolResult, any, error) {
		limit := 10
		if in.Limit > 0 {
			limit = in.Limit
		}
		result, err := client.GetTopSecurityThreats(limit, in.TimeRange)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Top Security Threats:\n%s", prettyJSON(result))}},
		}, nil, nil
	})

	// generate_security_report
	type SecurityReportInput struct {
		ReportType             string `json:"report_type" jsonschema:"description:Type of report (executive, technical, compliance)"`
		IncludeRecommendations bool   `json:"include_recommendations,omitempty" jsonschema:"description:Include AI-driven security recommendations"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "generate_security_report",
		Description: "Generate a detailed security posture report with optional recommendations",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in SecurityReportInput) (*mcp.CallToolResult, any, error) {
		result, err := client.GenerateSecurityReport(in.ReportType, in.IncludeRecommendations)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Security Report:\n%s", prettyJSON(result))}},
		}, nil, nil
	})

	// run_compliance_check
	type ComplianceCheckInput struct {
		Framework string `json:"framework" jsonschema:"description:Compliance framework (pci_dss, gdpr, hipaa, nist_800_53)"`
		AgentID   string `json:"agent_id,omitempty" jsonschema:"description:Optional target agent ID"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "run_compliance_check",
		Description: "Execute a compliance audit against specific frameworks (PCI-DSS, GDPR, etc.)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in ComplianceCheckInput) (*mcp.CallToolResult, any, error) {
		result, err := client.RunComplianceCheck(in.Framework, in.AgentID)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Compliance Check:\n%s", prettyJSON(result))}},
		}, nil, nil
	})
}
