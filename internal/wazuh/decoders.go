package wazuh

import (
	"encoding/json"
	"fmt"
)

// Decoder represents a Wazuh decoder
type Decoder struct {
	Parent      string   `json:"parent"`
	Position    string   `json:"position"`
	Status      string   `json:"status"`
	Name        string   `json:"name"`
	Filename    string   `json:"filename"`
	Description string   `json:"description"`
	Details     []string `json:"details"`
	Regex       string   `json:"regex"`
	Order       int      `json:"order"`
	ProgramName string   `json:"program_name"`
}

// GetDecoders retrieves all decoders
func (c *Client) GetDecoders(limit int, offset int, search string, sort string, order string) ([]Decoder, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if search != "" {
		req.SetQueryParam("search", search)
	}
	if sort != "" {
		req.SetQueryParam("sort", sort)
	}
	if order != "" {
		req.SetQueryParam("order", order)
	}

	resp, err := req.Get("/decoders")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting decoders: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Decoder `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetDecoderFiles retrieves decoder files
func (c *Client) GetDecoderFiles() ([]string, error) {
	resp, err := c.ManagerRequest().Get("/decoders/files")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting decoder files: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []string `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetDecodersByFile retrieves decoders from a specific file
func (c *Client) GetDecodersByFile(filename string, limit int, offset int) ([]Decoder, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"filename": filename}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	resp, err := req.Get("/decoders/files/{filename}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting decoders by file: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Decoder `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}
