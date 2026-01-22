package wazuh

import (
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
)

// ActiveResponseCommand represents an active response command
type ActiveResponseCommand struct {
	Command string                 `json:"command"`
	Custom  bool                   `json:"custom"`
	Args    []string               `json:"args"`
	ExtraArgs map[string]interface{} `json:"extra_args"`
}

// ExecuteActiveResponse executes an active response command
func (c *Client) ExecuteActiveResponse(agentID string, command ActiveResponseCommand) (interface{}, error) {
	body := map[string]interface{}{
		"command": command.Command,
		"custom":  command.Custom,
	}

	if len(command.Args) > 0 {
		body["arguments"] = command.Args
	}
	if len(command.ExtraArgs) > 0 {
		body["extra_args"] = command.ExtraArgs
	}

	var resp *resty.Response
	var err error

	if agentID != "" {
		resp, err = c.ManagerRequest().
			SetPathParams(map[string]string{"agent_id": agentID}).
			SetBody(body).
			Post("/active-response/{agent_id}")
	} else {
		resp, err = c.ManagerRequest().
			SetBody(body).
			Post("/active-response")
	}

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error executing active response: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetActiveResponseLogs retrieves active response logs
func (c *Client) GetActiveResponseLogs(limit int, offset int, sort string, search string) (interface{}, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if sort != "" {
		req.SetQueryParam("sort", sort)
	}
	if search != "" {
		req.SetQueryParam("search", search)
	}

	resp, err := req.Get("/active-response")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting active response logs: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
