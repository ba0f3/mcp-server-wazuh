package wazuh

import (
	"encoding/json"
	"fmt"
)

// CDBList represents a CDB list
type CDBList struct {
	Path    string `json:"path"`
	Items   int    `json:"items"`
	Key     string `json:"key"`
	Value   string `json:"value"`
}

// GetCDBLists retrieves all CDB lists
func (c *Client) GetCDBLists(limit int, offset int, search string, sort string, path string) ([]CDBList, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if search != "" {
		req.SetQueryParam("search", search)
	}
	if sort != "" {
		req.SetQueryParam("sort", sort)
	}
	if path != "" {
		req.SetQueryParam("path", path)
	}

	resp, err := req.Get("/lists")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting CDB lists: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []CDBList `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetCDBListFile retrieves a specific CDB list file
func (c *Client) GetCDBListFile(path string, limit int, offset int, search string, sort string) ([]CDBList, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"path": path}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if search != "" {
		req.SetQueryParam("search", search)
	}
	if sort != "" {
		req.SetQueryParam("sort", sort)
	}

	resp, err := req.Get("/lists/files/{path}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting CDB list file: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []CDBList `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}
