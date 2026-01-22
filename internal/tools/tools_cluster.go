package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerClusterTools(s *mcp.Server, client *wazuh.Client) {
	// get_wazuh_cluster_health
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_cluster_health",
		Description: "Retrieve health status and synchronization state of the Wazuh cluster",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		health, err := client.GetClusterHealth()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Cluster Health:\n%s", prettyJSON(health))}},
		}, nil, nil
	})

	// get_wazuh_cluster_nodes
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_wazuh_cluster_nodes",
		Description: "Retrieve a list of all nodes in the Wazuh cluster with their status",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		nodes, err := client.GetClusterNodes(100, 0, "")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Cluster Nodes:\n%s", prettyJSON(nodes))}},
		}, nil, nil
	})
}
