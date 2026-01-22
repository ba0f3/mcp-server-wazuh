package wazuh

import (
	"encoding/json"
	"fmt"
)

type Agent struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	IP                string   `json:"ip"`
	Status            string   `json:"status"`
	Version           string   `json:"version"`
	LastKeepAlive     string   `json:"lastKeepAlive"`
	DateAdd           string   `json:"dateAdd"`
	NodeName          string   `json:"node_name"`
	RegisterIP        string   `json:"registerIP"`
	Group             []string `json:"group"`
	GroupConfigStatus string   `json:"group_config_status"`
	OS                AgentOS  `json:"os"`
}

type AgentOS struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Platform string `json:"platform"`
}

func (c *Client) GetAgents(limit int, status, name, ip, group, osPlatform, version string) ([]Agent, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	if status != "" {
		req.SetQueryParam("status", status)
	}
	if name != "" {
		req.SetQueryParam("name", name)
	}
	if ip != "" {
		req.SetQueryParam("ip", ip)
	}
	if group != "" {
		req.SetQueryParam("group", group)
	}
	if osPlatform != "" {
		req.SetQueryParam("os_platform", osPlatform)
	}
	if version != "" {
		req.SetQueryParam("version", version)
	}

	resp, err := req.Get("/agents")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting agents: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Agent `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

func (c *Client) GetRunningAgents() ([]Agent, error) {
	return c.GetAgents(100, "active", "", "", "", "", "")
}

func (c *Client) GetAgentInfo(id string) (*Agent, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": id})

	resp, err := req.Get("/agents/{agent_id}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting agent info: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Agent `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	if len(result.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("agent not found")
	}

	return &result.Data.AffectedItems[0], nil
}

// FlexibleTime can unmarshal both number (Unix timestamp) and string values
type FlexibleTime struct {
	Value string
}

func (ft *FlexibleTime) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as number first
	var num float64
	if err := json.Unmarshal(data, &num); err == nil {
		ft.Value = fmt.Sprintf("%.0f", num)
		return nil
	}
	// If not a number, unmarshal as string
	return json.Unmarshal(data, &ft.Value)
}

func (ft FlexibleTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(ft.Value)
}

func (ft FlexibleTime) String() string {
	return ft.Value
}

// FlexibleInt can unmarshal both number and string values
type FlexibleInt struct {
	Value int
}

func (fi *FlexibleInt) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as number first
	var num int
	if err := json.Unmarshal(data, &num); err == nil {
		fi.Value = num
		return nil
	}
	// If not a number, try to unmarshal as string and parse
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		// Try to parse string as int
		var parsed int
		if _, err := fmt.Sscanf(str, "%d", &parsed); err == nil {
			fi.Value = parsed
			return nil
		}
	}
	return fmt.Errorf("cannot unmarshal %s into FlexibleInt", string(data))
}

func (fi FlexibleInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(fi.Value)
}

type Process struct {
	PID       FlexibleInt  `json:"pid"`
	Name      string       `json:"name"`
	State     string       `json:"state"`
	PPID      FlexibleInt  `json:"ppid"`
	EUser     string       `json:"euser"`
	Cmd       string       `json:"cmd"`
	StartTime FlexibleTime `json:"start_time"`
	Resident  int64        `json:"resident"`
	VMSize    int64        `json:"vm_size"`
}

func (c *Client) GetAgentProcesses(agentID string, limit int) ([]Process, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	resp, err := req.Get("/syscollector/{agent_id}/processes")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		if resp.StatusCode() == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("error getting agent processes: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Process `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

type Port struct {
	Protocol string `json:"protocol"`
	Local    struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"local"`
	Remote struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"remote"`
	State   string `json:"state"`
	PID     int    `json:"pid"`
	Process string `json:"process"`
	Inode   int    `json:"inode"`
	TXQueue int    `json:"tx_queue"`
	RXQueue int    `json:"rx_queue"`
}

func (c *Client) GetAgentPorts(agentID string, limit int) ([]Port, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	resp, err := req.Get("/syscollector/{agent_id}/netports")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		if resp.StatusCode() == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("error getting agent ports: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Port `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetAgentConfiguration retrieves agent configuration for a specific component
func (c *Client) GetAgentConfiguration(agentID, component, configuration string) (interface{}, error) {
	resp, err := c.ManagerRequest().
		SetPathParams(map[string]string{
			"agent_id":      agentID,
			"component":     component,
			"configuration": configuration,
		}).
		Get("/agents/{agent_id}/config/{component}/{configuration}")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting agent configuration: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAgentSummaryOS retrieves a summary of agents grouped by OS
func (c *Client) GetAgentSummaryOS() (interface{}, error) {
	resp, err := c.ManagerRequest().Get("/agents/summary/os")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting agent OS summary: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAgentSummaryStatus retrieves a summary of agents grouped by status
func (c *Client) GetAgentSummaryStatus() (interface{}, error) {
	resp, err := c.ManagerRequest().Get("/agents/summary/status")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting agent status summary: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAgentGroups retrieves all agent groups
func (c *Client) GetAgentGroups() (interface{}, error) {
	resp, err := c.ManagerRequest().Get("/groups")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting agent groups: %s", resp.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAgentDistinctStats retrieves distinct statistics for a specific field
// Note: The API endpoint /agents/stats/distinct doesn't accept a 'field' query parameter
// Instead, use /agents/stats/distinct?field=<field_name> but check API documentation
func (c *Client) GetAgentDistinctStats(field string) (interface{}, error) {
	req := c.ManagerRequest()
	// Only add field parameter if it's not empty and the API supports it
	// Some API versions may not support this parameter
	if field != "" {
		// Try with field parameter - may fail on some API versions
		req = req.SetQueryParam("field", field)
	}

	resp, err := req.Get("/agents/stats/distinct")

	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		// If error is due to field parameter, try without it
		if field != "" && (resp.StatusCode() == 400 || resp.StatusCode() == 422) {
			resp, err = c.ManagerRequest().Get("/agents/stats/distinct")
			if err != nil {
				return nil, err
			}
			if resp.IsError() {
				return nil, fmt.Errorf("error getting agent distinct stats: %s", resp.String())
			}
		} else {
			return nil, fmt.Errorf("error getting agent distinct stats: %s", resp.String())
		}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}
