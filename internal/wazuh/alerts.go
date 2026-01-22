package wazuh

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"
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

// parseTimeRange converts a time range string (e.g., "24h", "7d") to start and end timestamps
func parseTimeRange(timeRange string) (string, string, error) {
	if timeRange == "" {
		timeRange = "24h"
	}
	now := time.Now()
	var duration time.Duration
	re := regexp.MustCompile(`^(\d+)([hdms])$`)
	matches := re.FindStringSubmatch(timeRange)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid time range format: %s (expected format: 24h, 7d, etc.)", timeRange)
	}
	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid time range value: %s", timeRange)
	}
	unit := matches[2]
	switch unit {
	case "h":
		duration = time.Duration(value) * time.Hour
	case "d":
		duration = time.Duration(value) * 24 * time.Hour
	case "m":
		duration = time.Duration(value) * time.Minute
	case "s":
		duration = time.Duration(value) * time.Second
	default:
		return "", "", fmt.Errorf("invalid time range unit: %s (expected: h, d, m, s)", unit)
	}
	startTime := now.Add(-duration)
	return startTime.Format(time.RFC3339), now.Format(time.RFC3339), nil
}

func (c *Client) AnalyzeAlertPatterns(timeRange string, minFrequency int) (interface{}, error) {
	// Parse time range to get timestamp boundaries
	timestampStart, timestampEnd, err := parseTimeRange(timeRange)
	if err != nil {
		return nil, fmt.Errorf("error parsing time range: %w", err)
	}
	// Query alerts from the indexer
	alerts, err := c.GetAlerts(10000, "", "", "", timestampStart, timestampEnd)
	if err != nil {
		return nil, fmt.Errorf("error fetching alerts for pattern analysis: %w", err)
	}
	// Analyze patterns: group by rule ID and count occurrences
	patternMap := make(map[string]map[string]interface{})
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
		ruleIDStr := fmt.Sprintf("%.0f", ruleID)
		if patternMap[ruleIDStr] == nil {
			patternMap[ruleIDStr] = map[string]interface{}{
				"rule_id":     ruleID,
				"description": rule["description"],
				"level":       rule["level"],
				"frequency":   0,
			}
		}
		freq, _ := patternMap[ruleIDStr]["frequency"].(int)
		patternMap[ruleIDStr]["frequency"] = freq + 1
	}
	// Filter by minimum frequency and convert to list
	patterns := []map[string]interface{}{}
	for _, pattern := range patternMap {
		freq, _ := pattern["frequency"].(int)
		if freq >= minFrequency {
			patterns = append(patterns, pattern)
		}
	}
	result := map[string]interface{}{
		"time_range":     timeRange,
		"min_frequency":  minFrequency,
		"total_alerts":   len(alerts),
		"patterns_found": len(patterns),
		"patterns":       patterns,
	}
	return result, nil
}

func (c *Client) SearchSecurityEvents(query string, timeRange string, limit int) (interface{}, error) {
	// Parse time range to get timestamp boundaries
	timestampStart, timestampEnd, err := parseTimeRange(timeRange)
	if err != nil {
		return nil, fmt.Errorf("error parsing time range: %w", err)
	}
	// Build query clauses
	mustClauses := []map[string]interface{}{}
	// Add time range filter
	mustClauses = append(mustClauses, map[string]interface{}{
		"range": map[string]interface{}{
			"timestamp": map[string]interface{}{
				"gte": timestampStart,
				"lte": timestampEnd,
			},
		},
	})
	// If query is provided, add a multi-match query for common fields
	if query != "" && query != "*" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  query,
				"fields": []string{"rule.description", "rule.id", "agent.name", "data.srcip", "data.dstip", "full_log"},
				"type":   "best_fields",
			},
		})
	}
	// Build the query
	var esQuery map[string]interface{}
	if len(mustClauses) > 0 {
		esQuery = map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		}
	} else {
		esQuery = map[string]interface{}{"match_all": map[string]interface{}{}}
	}
	// Build request body
	body := map[string]interface{}{
		"query": esQuery,
		"size":  limit,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}
	// Execute search against indexer
	resp, err := c.IndexerRequest().
		SetBody(body).
		Post("/wazuh-alerts-*/_search")
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, fmt.Errorf("error searching security events: %s", resp.String())
	}
	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []map[string]interface{} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}
	// Format response
	formattedResult := map[string]interface{}{
		"query":      query,
		"time_range": timeRange,
		"total":      result.Hits.Total.Value,
		"returned":   len(result.Hits.Hits),
		"events":     result.Hits.Hits,
	}
	return formattedResult, nil
}

type ThreatEntry struct {
	RuleID      float64
	Level       float64
	Description string
	Count       int
}

// GetTopSecurityThreats identifies top security threats by analyzing alerts from the indexer
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
