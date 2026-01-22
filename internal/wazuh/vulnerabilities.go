package wazuh

import (
	"encoding/json"
	"fmt"
)

type Vulnerability struct {
	CVE           string                `json:"cve"`
	Severity      string                `json:"severity"`
	Title         string                `json:"title"`
	Description   string                `json:"description"`
	Published     string                `json:"published"`
	Updated       string                `json:"updated"`
	DetectionTime string                `json:"detection_time"`
	AgentID       string                `json:"agent_id"`
	AgentName     string                `json:"agent_name"`
	CVSS          *VulnerabilityCVSS    `json:"cvss"`
	Reference     string                `json:"reference"`
}

type VulnerabilityCVSS struct {
	CVSS2 *CVSSScore `json:"cvss2"`
	CVSS3 *CVSSScore `json:"cvss3"`
}

type CVSSScore struct {
	BaseScore float64 `json:"base_score"`
}

func (c *Client) GetAgentVulnerabilities(agentID string, limit int, severity string) ([]Vulnerability, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	if severity != "" {
		req.SetQueryParam("severity", severity)
	}

	resp, err := req.Get("/vulnerability/{agent_id}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		if resp.StatusCode() == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("error getting agent vulnerabilities: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Vulnerability `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}
