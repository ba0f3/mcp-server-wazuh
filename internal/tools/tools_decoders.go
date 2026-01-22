package tools

import (
	"context"
	"fmt"

	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerDecoderTools(s *mcp.Server, client *wazuh.Client) {
	// get_decoders
	type GetDecodersInput struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
		Search string `json:"search,omitempty" jsonschema:"description:Search term"`
		Sort   string `json:"sort,omitempty" jsonschema:"description:Sort field"`
		Order  string `json:"order,omitempty" jsonschema:"description:Sort order (asc/desc)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_decoders",
		Description: "Retrieve all Wazuh decoders (log parsing rules)",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetDecodersInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		decoders, err := client.GetDecoders(limit, in.Offset, in.Search, in.Sort, in.Order)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Decoders:\n%s", prettyJSON(decoders))}},
		}, nil, nil
	})

	// get_decoder_files
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_decoder_files",
		Description: "Retrieve list of decoder files",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		files, err := client.GetDecoderFiles()
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Decoder Files:\n%s", prettyJSON(files))}},
		}, nil, nil
	})

	// get_decoders_by_file
	type GetDecodersByFileInput struct {
		Filename string `json:"filename" jsonschema:"description:Decoder filename"`
		Limit    int    `json:"limit,omitempty" jsonschema:"description:Maximum results (default: 100)"`
		Offset   int    `json:"offset,omitempty" jsonschema:"description:Offset for pagination (default: 0)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_decoders_by_file",
		Description: "Retrieve decoders from a specific file",
	}, func(ctx context.Context, request *mcp.CallToolRequest, in GetDecodersByFileInput) (*mcp.CallToolResult, any, error) {
		limit := 100
		if in.Limit > 0 {
			limit = in.Limit
		}
		decoders, err := client.GetDecodersByFile(in.Filename, limit, in.Offset)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
				IsError: true,
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Decoders from %s:\n%s", in.Filename, prettyJSON(decoders))}},
		}, nil, nil
	})
}
