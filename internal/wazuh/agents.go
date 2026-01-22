package wazuh

import (
	"encoding/json"
	"fmt"
)

type Agent struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	IP                 string   `json:"ip"`
	Status             string   `json:"status"`
	Version            string   `json:"version"`
	LastKeepAlive      string   `json:"lastKeepAlive"`
	DateAdd            string   `json:"dateAdd"`
	NodeName           string   `json:"node_name"`
	RegisterIP         string   `json:"registerIP"`
	Group              []string `json:"group"`
	GroupConfigStatus  string   `json:"group_config_status"`
	OS                 AgentOS  `json:"os"`
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

type Process struct {
	PID       int    `json:"pid"`
	Name      string `json:"name"`
	State     string `json:"state"`
	PPID      int    `json:"ppid"`
	EUser     string `json:"euser"`
	Cmd       string `json:"cmd"`
	StartTime string `json:"start_time"`
	Resident  int64  `json:"resident"`
	VMSize    int64  `json:"vm_size"`
}

func (c *Client) GetAgentProcesses(agentID string, limit int, search string) ([]Process, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	if search != "" {
		req.SetQueryParam("search", search)
	}

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

func (c *Client) GetAgentPorts(agentID string, limit int, protocol string) ([]Port, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"agent_id": agentID}).
		SetQueryParam("limit", fmt.Sprintf("%d", limit))

	if protocol != "" {
		req.SetQueryParam("protocol", protocol)
	}

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
