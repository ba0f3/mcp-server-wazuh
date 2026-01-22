package wazuh

import (
	"encoding/json"
	"fmt"
)

type Vulnerability struct {
	CVE           string             `json:"cve"`
	Severity      string             `json:"severity"`
	Title         string             `json:"title"`
	Description   string             `json:"description"`
	Published     string             `json:"published"`
	Updated       string             `json:"updated"`
	DetectionTime string             `json:"detection_time"`
	AgentID       string             `json:"agent_id"`
	AgentName     string             `json:"agent_name"`
	CVSS          *VulnerabilityCVSS `json:"cvss"`
	Reference     string             `json:"reference"`
}

type VulnerabilityCVSS struct {
	CVSS2 *CVSSScore `json:"cvss2"`
	CVSS3 *CVSSScore `json:"cvss3"`
}

type CVSSScore struct {
	BaseScore float64 `json:"base_score"`
}

func (c *Client) GetVulnerabilities(agentID, severity string, limit int) ([]Vulnerability, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	if severity != "" {
		req.SetQueryParam("severity", severity)
	}

	var endpoint string
	if agentID != "" {
		req.SetPathParams(map[string]string{"agent_id": agentID})
		endpoint = "/vulnerability/{agent_id}"
	} else {
		endpoint = "/vulnerability"
	}

	resp, err := req.Get(endpoint)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		if resp.StatusCode() == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("error getting vulnerabilities: %s", resp.String())
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

func (c *Client) GetVulnerabilitiesSummary(agentID string) (interface{}, error) {
	req := c.ManagerRequest()
	var endpoint string
	if agentID != "" {
		req.SetPathParams(map[string]string{"agent_id": agentID})
		endpoint = "/vulnerability/{agent_id}/summary"
	} else {
		endpoint = "/vulnerability/summary"
	}

	resp, err := req.Get(endpoint)
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting vulnerabilities summary: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) GetCriticalVulnerabilities(limit int) (interface{}, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"vulnerability.severity": "Critical",
			},
		},
		"size": limit,
	}

	resp, err := c.IndexerRequest().
		SetBody(query).
		Post("/wazuh-states-vulnerabilities-*/_search")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error searching critical vulnerabilities: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) GetVulnerabilitySummaryIndexer() (interface{}, error) {
	query := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "vulnerability.severity",
					"size":  10,
				},
			},
			"by_agent": map[string]interface{}{
				"cardinality": map[string]interface{}{
					"field": "agent.id",
				},
			},
			"total_vulnerabilities": map[string]interface{}{
				"value_count": map[string]interface{}{
					"field": "vulnerability.id",
				},
			},
		},
	}

	resp, err := c.IndexerRequest().
		SetBody(query).
		Post("/wazuh-states-vulnerabilities-*/_search")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting vulnerability summary from indexer: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
