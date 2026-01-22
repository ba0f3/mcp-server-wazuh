package wazuh

import (
	"encoding/json"
	"fmt"
)

func (c *Client) AnalyzeSecurityThreat(indicator string, indicatorType string) (interface{}, error) {
	body := map[string]interface{}{
		"indicator": indicator,
		"type":      indicatorType,
	}

	resp, err := c.ManagerRequest().
		SetBody(body).
		Post("/security/threat/analyze")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error analyzing security threat: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) CheckIOCReputation(indicator string, indicatorType string) (interface{}, error) {
	params := map[string]string{
		"indicator": indicator,
		"type":      indicatorType,
	}

	resp, err := c.ManagerRequest().
		SetQueryParams(params).
		Get("/security/ioc/reputation")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error checking IOC reputation: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) PerformRiskAssessment(agentID string) (interface{}, error) {
	endpoint := "/security/risk"
	if agentID != "" {
		endpoint = fmt.Sprintf("/security/risk/%s", agentID)
	}

	resp, err := c.ManagerRequest().Get(endpoint)

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error performing risk assessment: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) GetTopSecurityThreats(limit int, timeRange string) (interface{}, error) {
	params := map[string]string{
		"limit": fmt.Sprintf("%d", limit),
	}
	if timeRange != "" {
		params["time_range"] = timeRange
	}

	resp, err := c.ManagerRequest().
		SetQueryParams(params).
		Get("/security/threats/top")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting top security threats: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) GenerateSecurityReport(reportType string, includeRecommendations bool) (interface{}, error) {
	body := map[string]interface{}{
		"type":                   reportType,
		"include_recommendations": includeRecommendations,
	}

	resp, err := c.ManagerRequest().
		SetBody(body).
		Post("/security/reports/generate")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error generating security report: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) RunComplianceCheck(framework string, agentID string) (interface{}, error) {
	body := map[string]interface{}{
		"framework": framework,
	}
	if agentID != "" {
		body["agent_id"] = agentID
	}

	resp, err := c.ManagerRequest().
		SetBody(body).
		Post("/security/compliance/check")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error running compliance check: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
