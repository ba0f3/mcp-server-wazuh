package wazuh

import (
	"encoding/json"
	"fmt"
)

// RootcheckItem represents a rootcheck result
type RootcheckItem struct {
	Status      string `json:"status"`
	Log         string `json:"log"`
	Type        string `json:"type"`
	Date        string `json:"date"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// GetRootcheckDatabase retrieves rootcheck database for an agent
func (c *Client) GetRootcheckDatabase(agentID string, limit int, offset int, sort string, search string, status string, type_ string) ([]RootcheckItem, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if sort != "" {
		req.SetQueryParam("sort", sort)
	}
	if search != "" {
		req.SetQueryParam("search", search)
	}
	if status != "" {
		req.SetQueryParam("status", status)
	}
	if type_ != "" {
		req.SetQueryParam("type", type_)
	}

	resp, err := req.Get("/rootcheck/{agent_id}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting rootcheck database: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []RootcheckItem `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetRootcheckLastScan retrieves the last rootcheck scan time for an agent
func (c *Client) GetRootcheckLastScan(agentID string) (interface{}, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID})

	resp, err := req.Get("/rootcheck/{agent_id}/last_scan")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting rootcheck last scan: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
