package wazuh

import (
	"encoding/json"
	"fmt"
)

func (c *Client) GetAlerts(limit int) ([]map[string]interface{}, error) {
	query := map[string]interface{}{
		"size": limit,
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	resp, err := c.IndexerRequest().
		SetBody(query).
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
