package wazuh

import (
	"encoding/json"
	"fmt"
)

type Rule struct {
	ID          int      `json:"id"`
	Level       int      `json:"level"`
	Description string   `json:"description"`
	Groups      []string `json:"groups"`
	Filename    string   `json:"filename"`
	Status      string   `json:"status"`
	GDPR        []string `json:"gdpr"`
	HIPAA       []string `json:"hipaa"`
	PCIDSS      []string `json:"pci_dss"`
	NIST800_53  []string `json:"nist_800_53"`
}

func (c *Client) GetRules(limit int, level *uint32, group, filename string) ([]Rule, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	if level != nil {
		req.SetQueryParam("level", fmt.Sprintf("%d", *level))
	}
	if group != "" {
		req.SetQueryParam("group", group)
	}
	if filename != "" {
		req.SetQueryParam("filename", filename)
	}

	resp, err := req.Get("/rules")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting rules: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Rule `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

func (c *Client) GetRuleInfo(id int) (*Rule, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"rule_id": fmt.Sprintf("%d", id)})

	resp, err := req.Get("/rules/{rule_id}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting rule info: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Rule `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	if len(result.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("rule not found")
	}

	return &result.Data.AffectedItems[0], nil
}

// GetRulesSummary retrieves rules summary by querying /rules endpoint and aggregating locally
func (c *Client) GetRulesSummary() (interface{}, error) {
	// Get all rules (with a reasonable limit)
	rules, err := c.GetRules(1000, nil, "", "")
	if err != nil {
		return nil, fmt.Errorf("error fetching rules: %w", err)
	}

	// Aggregate statistics
	levelCount := make(map[int]int)
	statusCount := make(map[string]int)
	groupCount := make(map[string]int)
	totalRules := len(rules)

	for _, rule := range rules {
		levelCount[rule.Level]++
		statusCount[rule.Status]++
		for _, group := range rule.Groups {
			groupCount[group]++
		}
	}

	// Format level summary
	levelSummary := []map[string]interface{}{}
	for level, count := range levelCount {
		levelSummary = append(levelSummary, map[string]interface{}{
			"level": level,
			"count": count,
		})
	}

	// Format status summary
	statusSummary := []map[string]interface{}{}
	for status, count := range statusCount {
		statusSummary = append(statusSummary, map[string]interface{}{
			"status": status,
			"count":  count,
		})
	}

	// Format group summary (top 10)
	groupSummary := []map[string]interface{}{}
	for group, count := range groupCount {
		groupSummary = append(groupSummary, map[string]interface{}{
			"group": group,
			"count": count,
		})
	}

	result := map[string]interface{}{
		"total_rules":    totalRules,
		"by_level":       levelSummary,
		"by_status":      statusSummary,
		"by_group":       groupSummary,
		"total_groups":   len(groupCount),
	}

	return result, nil
}
