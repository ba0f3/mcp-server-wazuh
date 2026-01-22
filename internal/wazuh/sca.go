package wazuh

import (
	"encoding/json"
	"fmt"
)

// SCAPolicy represents a SCA policy
type SCAPolicy struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	References  []string `json:"references"`
	File        string `json:"file"`
}

// SCACheck represents a SCA check result
type SCACheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Rationale   string `json:"rationale"`
	Remediation string `json:"remediation"`
	Compliance  map[string]interface{} `json:"compliance"`
	Status      string `json:"status"`
	Result      string `json:"result"`
	Reason      string `json:"reason"`
	Condition   string `json:"condition"`
}

// GetSCAPolicies retrieves SCA policies for an agent
func (c *Client) GetSCAPolicies(agentID string, limit int, offset int) ([]SCAPolicy, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	resp, err := req.Get("/sca/{agent_id}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting SCA policies: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []SCAPolicy `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetSCAPolicyChecks retrieves checks for a specific SCA policy
func (c *Client) GetSCAPolicyChecks(agentID, policyID string, limit int, offset int) ([]SCACheck, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{
			"agent_id": agentID,
			"policy_id": policyID,
		}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	resp, err := req.Get("/sca/{agent_id}/checks/{policy_id}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting SCA policy checks: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []SCACheck `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetSCASummary retrieves a summary of SCA results for an agent
func (c *Client) GetSCASummary(agentID string) (interface{}, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID})

	resp, err := req.Get("/sca/{agent_id}/summary")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting SCA summary: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
