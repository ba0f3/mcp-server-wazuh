package wazuh

import (
	"encoding/json"
	"fmt"
)

type ClusterHealth struct {
	Enabled string `json:"enabled"`
	Running string `json:"running"`
}

func (c *Client) GetClusterHealth() (*ClusterHealth, error) {
	resp, err := c.ManagerRequest().Get("/cluster/status")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting cluster health: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []ClusterHealth `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	if len(result.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("no cluster health info found")
	}

	return &result.Data.AffectedItems[0], nil
}

type ClusterNode struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
	IP      string `json:"ip"`
	Status  string `json:"status"`
}

func (c *Client) GetClusterNodes(limit int, offset int, nodeType string) ([]ClusterNode, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if nodeType != "" {
		req.SetQueryParam("type", nodeType)
	}

	resp, err := req.Get("/cluster/nodes")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting cluster nodes: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []ClusterNode `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

type LogEntry struct {
	Timestamp   string `json:"timestamp"`
	Tag         string `json:"tag"`
	Level       string `json:"level"`
	Description string `json:"description"`
}

func (c *Client) GetManagerLogs(limit int, offset int, level string, tag string, search string) ([]LogEntry, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if level != "" {
		req.SetQueryParam("level", level)
	}
	if tag != "" {
		req.SetQueryParam("tag", tag)
	}
	if search != "" {
		req.SetQueryParam("search", search)
	}

	resp, err := req.Get("/manager/logs")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting manager logs: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []LogEntry `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

func (c *Client) GetLogCollectorStats(agentID string) (interface{}, error) {
	req := c.ManagerRequest()
	var endpoint string
	if agentID != "" {
		req.SetPathParams(map[string]string{"agent_id": agentID})
		endpoint = "/agents/{agent_id}/stats/logcollector"
	} else {
		endpoint = "/manager/stats/logcollector"
	}

	resp, err := req.Get(endpoint)

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting logcollector stats: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}


func (c *Client) GetWeeklyStats() (interface{}, error) {
	resp, err := c.ManagerRequest().Get("/manager/stats/weekly")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting weekly stats: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetManagerDaemonStats retrieves manager daemon statistics (replaces deprecated /manager/stats/all)
func (c *Client) GetManagerDaemonStats() (interface{}, error) {
	resp, err := c.ManagerRequest().Get("/manager/daemons/stats")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting manager daemon stats: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAgentDaemonStats retrieves daemon statistics for a specific agent
func (c *Client) GetAgentDaemonStats(agentID string) (interface{}, error) {
	resp, err := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		Get("/agents/{agent_id}/daemons/stats")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting agent daemon stats: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) ValidateConnection() (interface{}, error) {
	resp, err := c.ManagerRequest().Get("/")

	if err != nil {
		return map[string]interface{}{"status": "failed", "error": err.Error()}, nil
	}

	if resp.IsError() {
		return map[string]interface{}{"status": "failed", "error": resp.String()}, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return map[string]interface{}{"status": "failed", "error": err.Error()}, nil
	}

	return map[string]interface{}{"status": "connected", "details": result}, nil
}
