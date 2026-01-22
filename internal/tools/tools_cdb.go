package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerCDBTools(s *mcp.Server, client *wazuh.Client) {
	// get_cdb_lists
	type GetCDBListsInput struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Search string `json:"search,omitempty" jsonschema:"description:Search term"`
		Sort   string `json:"sort,omitempty" jsonschema:"description:Sort field"`
		Path   string `json:"path,omitempty" jsonschema:"description:Filter by path"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_cdb_lists",
		Description: "Retrieve all CDB (Custom Database) lists",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetCDBListsInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		lists, err := client.GetCDBLists(limit, in.Offset, in.Search, in.Sort, in.Path)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("CDB Lists:\n%s", prettyJSON(lists))}},
		}, nil, nil
	})

	// get_cdb_list_file
	type GetCDBListFileInput struct {
		Path   string `json:"path" jsonschema:"description:CDB list file path"`
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Search string `json:"search,omitempty" jsonschema:"description:Search term"`
		Sort   string `json:"sort,omitempty" jsonschema:"description:Sort field"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_cdb_list_file",
		Description: "Retrieve entries from a specific CDB list file",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetCDBListFileInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		items, err := client.GetCDBListFile(in.Path, limit, in.Offset, in.Search, in.Sort)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("CDB List File:\n%s", prettyJSON(items))}},
		}, nil, nil
	})
}
