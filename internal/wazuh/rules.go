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

func (c *Client) GetRulesSummary() (interface{}, error) {
	resp, err := c.ManagerRequest().Get("/rules/summary")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting rules summary: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
