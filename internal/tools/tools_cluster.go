package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerClusterTools registers cluster-related tools
func registerClusterTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_cluster_health
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_cluster_health",
		Description: "Checks the health of the Wazuh cluster. Returns whether the cluster is enabled, running, and if nodes are connected.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
		health, err := client.GetClusterHealth()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving cluster health: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		formattedText := fmt.Sprintf("Cluster Enabled: %s\nCluster Running: %s", health.Enabled, health.Running)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: formattedText}},
		}, nil, nil
	})

	// get_wazuh_cluster_nodes
	type ClusterNodesInput struct {
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum number of nodes to retrieve (default: 300)"`
		Offset   int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		NodeType string `json:"node_type,omitempty" jsonschema:"description:Node type to filter by (worker, master) (optional)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_cluster_nodes",
		Description: "Retrieves a list of nodes in the Wazuh cluster. Returns formatted node information including name, type, version, IP, and status. Supports filtering by limit, offset, and node type.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in ClusterNodesInput) (*mcp.CallToolResult, any, error) {
		limit := 300
		if in.Limit > 0 {
			limit = in.Limit
		}

		nodes, err := client.GetClusterNodes(limit, in.Offset, in.NodeType)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error retrieving cluster nodes: %v", err)}},
				IsError: true,
			}, nil, nil
		}

		if len(nodes) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No cluster nodes found matching the specified criteria."}},
			}, nil, nil
		}

		var items []mcp.Content
		for _, node := range nodes {
			formattedText := fmt.Sprintf("Node Name: %s\nType: %s\nVersion: %s\nIP: %s\nStatus: %s",
				node.Name, node.Type, node.Version, node.IP, node.Status)
			items = append(items, &mcp.TextContent{Text: formattedText})
		}

		return &mcp.CallToolResult{Content: items}, nil, nil
	})
}
