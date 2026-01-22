package wazuh

import (
	"encoding/json"
	"fmt"
	"sort"
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
		if resp.StatusCode() == 404 {
			return nil, fmt.Errorf("security threat analysis endpoint not found (404): the /security/threat/analyze endpoint is not available in this Wazuh installation. This endpoint may require a custom Wazuh extension or module")
		}
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
		// Check if the endpoint doesn't exist (404)
		if resp.StatusCode() == 404 {
			return nil, fmt.Errorf("IOC reputation endpoint not found (404): the /security/ioc/reputation endpoint is not available in this Wazuh installation. This endpoint may require a custom Wazuh extension or module")
		}
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
		if resp.StatusCode() == 404 {
			return nil, fmt.Errorf("risk assessment endpoint not found (404): the /security/risk endpoint is not available in this Wazuh installation. This endpoint may require a custom Wazuh extension or module")
		}
		return nil, fmt.Errorf("error performing risk assessment: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

type ThreatEntry struct {
	RuleID      float64
	Level       float64
	Description string
	Count       int
}

func (c *Client) GetTopSecurityThreats(limit int, timeRange string) (interface{}, error) {
	// Parse time range to get timestamp boundaries
	timestampStart, timestampEnd, err := parseTimeRange(timeRange)
	if err != nil {
		return nil, fmt.Errorf("error parsing time range: %w", err)
	}
	// Query alerts from the indexer, focusing on higher severity alerts (level >= 7)
	alerts, err := c.GetAlerts(10000, "", "", "", timestampStart, timestampEnd)
	if err != nil {
		return nil, fmt.Errorf("error fetching alerts for threat analysis: %w", err)
	}
	// Aggregate threats by rule ID, prioritizing higher severity
	threatMap := make(map[string]*ThreatEntry)
	for _, alert := range alerts {
		source, ok := alert["_source"].(map[string]interface{})
		if !ok {
			continue
		}
		rule, ok := source["rule"].(map[string]interface{})
		if !ok {
			continue
		}
		ruleID, ok := rule["id"].(float64)
		if !ok {
			continue
		}
		ruleLevel, _ := rule["level"].(float64)
		// Focus on medium to critical severity (level >= 7)
		if ruleLevel < 7 {
			continue
		}
		ruleIDStr := fmt.Sprintf("%.0f", ruleID)
		if threatMap[ruleIDStr] == nil {
			description, _ := rule["description"].(string)
			threatMap[ruleIDStr] = &ThreatEntry{
				RuleID:      ruleID,
				Level:       ruleLevel,
				Description: description,
				Count:       0,
			}
		}
		threatMap[ruleIDStr].Count++
	}
	// Convert to slice and sort by count (descending), then by level (descending)
	threats := make([]*ThreatEntry, 0, len(threatMap))
	for _, threat := range threatMap {
		threats = append(threats, threat)
	}
	sort.Slice(threats, func(i, j int) bool {
		if threats[i].Count != threats[j].Count {
			return threats[i].Count > threats[j].Count
		}
		return threats[i].Level > threats[j].Level
	})
	// Limit results
	if limit > 0 && len(threats) > limit {
		threats = threats[:limit]
	}
	// Format response
	threatList := make([]map[string]interface{}, len(threats))
	for i, threat := range threats {
		threatList[i] = map[string]interface{}{
			"rule_id":     threat.RuleID,
			"level":       threat.Level,
			"description": threat.Description,
			"occurrences": threat.Count,
		}
	}
	result := map[string]interface{}{
		"time_range": timeRange,
		"limit":      limit,
		"total":      len(threatList),
		"threats":    threatList,
	}
	return result, nil
}

func (c *Client) GenerateSecurityReport(reportType string, includeRecommendations bool) (interface{}, error) {
	body := map[string]interface{}{
		"type":                    reportType,
		"include_recommendations": includeRecommendations,
	}

	resp, err := c.ManagerRequest().
		SetBody(body).
		Post("/security/reports/generate")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		if resp.StatusCode() == 404 {
			return nil, fmt.Errorf("security report endpoint not found (404): the /security/reports/generate endpoint is not available in this Wazuh installation. This endpoint may require a custom Wazuh extension or module")
		}
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
		if resp.StatusCode() == 404 {
			return nil, fmt.Errorf("compliance check endpoint not found (404): the /security/compliance/check endpoint is not available in this Wazuh installation. This endpoint may require a custom Wazuh extension or module")
		}
		return nil, fmt.Errorf("error running compliance check: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
