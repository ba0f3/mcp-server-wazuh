package wazuh

import (
	"encoding/json"
	"fmt"
)

// MITRETechnique represents a MITRE ATT&CK technique
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactic      []string `json:"tactic"`
	Platform    []string `json:"platform"`
}

// GetMITRETechniques retrieves MITRE ATT&CK techniques
func (c *Client) GetMITRETechniques(limit int, offset int, q string, select_ string, sort string) ([]MITRETechnique, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if q != "" {
		req.SetQueryParam("q", q)
	}
	if select_ != "" {
		req.SetQueryParam("select", select_)
	}
	if sort != "" {
		req.SetQueryParam("sort", sort)
	}

	resp, err := req.Get("/mitre")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting MITRE techniques: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []MITRETechnique `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetMITRETechniqueByID retrieves a specific MITRE technique by ID
func (c *Client) GetMITRETechniqueByID(techniqueID string) (*MITRETechnique, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"technique_id": techniqueID})

	resp, err := req.Get("/mitre/{technique_id}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting MITRE technique: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []MITRETechnique `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	if len(result.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("MITRE technique not found")
	}

	return &result.Data.AffectedItems[0], nil
}

// GetMITREAgents retrieves agents with MITRE techniques
func (c *Client) GetMITREAgents(limit int, offset int, q string, select_ string, sort string) (interface{}, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if q != "" {
		req.SetQueryParam("q", q)
	}
	if select_ != "" {
		req.SetQueryParam("select", select_)
	}
	if sort != "" {
		req.SetQueryParam("sort", sort)
	}

	resp, err := req.Get("/mitre/agents")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting MITRE agents: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
