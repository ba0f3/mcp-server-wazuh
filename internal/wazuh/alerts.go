package wazuh

import (
	"encoding/json"
	"fmt"
)

func (c *Client) GetAlerts(limit int, ruleID, level, agentID, timestampStart, timestampEnd string) ([]map[string]interface{}, error) {
	mustClauses := []map[string]interface{}{}

	if ruleID != "" {
		mustClauses = append(mustClauses, map[string]interface{}{"match": map[string]interface{}{"rule.id": ruleID}})
	}
	if level != "" {
		mustClauses = append(mustClauses, map[string]interface{}{"match": map[string]interface{}{"rule.level": level}})
	}
	if agentID != "" {
		mustClauses = append(mustClauses, map[string]interface{}{"match": map[string]interface{}{"agent.id": agentID}})
	}

	rangeClause := map[string]interface{}{}
	if timestampStart != "" {
		rangeClause["gte"] = timestampStart
	}
	if timestampEnd != "" {
		rangeClause["lte"] = timestampEnd
	}

	if len(rangeClause) > 0 {
		mustClauses = append(mustClauses, map[string]interface{}{"range": map[string]interface{}{"timestamp": rangeClause}})
	}

	var query map[string]interface{}
	if len(mustClauses) > 0 {
		query = map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		}
	} else {
		query = map[string]interface{}{"match_all": map[string]interface{}{}}
	}

	body := map[string]interface{}{
		"query": query,
		"size":  limit,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	resp, err := c.IndexerRequest().
		SetBody(body).
		Post("/wazuh-alerts-*/_search")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error searching alerts: %s", resp.String())
	}

	var result struct {
		Hits struct {
			Hits []map[string]interface{} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Hits.Hits, nil
}

func (c *Client) GetAlertSummary(timeRange string, groupBy string) (interface{}, error) {
	params := map[string]string{}
	if timeRange != "" {
		params["time_range"] = timeRange
	}
	if groupBy != "" {
		params["group_by"] = groupBy
	}

	// NOTE: This endpoint might not be available in all Wazuh versions.
	// It's used in the reference project.
	resp, err := c.ManagerRequest().
		SetQueryParams(params).
		Get("/alerts/summary")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting alert summary: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) AnalyzeAlertPatterns(timeRange string, minFrequency int) (interface{}, error) {
	params := map[string]string{
		"min_frequency": fmt.Sprintf("%d", minFrequency),
	}
	if timeRange != "" {
		params["time_range"] = timeRange
	}

	// NOTE: This endpoint might not be available in all Wazuh versions.
	resp, err := c.ManagerRequest().
		SetQueryParams(params).
		Get("/alerts/patterns")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error analyzing alert patterns: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) SearchSecurityEvents(query string, timeRange string, limit int) (interface{}, error) {
	params := map[string]string{
		"limit": fmt.Sprintf("%d", limit),
	}
	if query != "" {
		params["q"] = query
	}
	if timeRange != "" {
		params["time_range"] = timeRange
	}

	// NOTE: This endpoint might not be available in all Wazuh versions.
	resp, err := c.ManagerRequest().
		SetQueryParams(params).
		Get("/security/events")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error searching security events: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
