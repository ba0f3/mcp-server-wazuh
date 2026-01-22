package tools

import (
	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterTools registers all MCP tools with the server
func RegisterTools(s *mcp.Server, client *wazuh.Client) {
	registerAlertTools(s, client)
	registerRulesTools(s, client)
	registerVulnerabilityTools(s, client)
	registerAgentTools(s, client)
	registerClusterTools(s, client)
	registerLogTools(s, client)
	registerStatsTools(s, client)
	// Experimental APIs
	registerSCATools(s, client)
	registerDecoderTools(s, client)
	registerRootcheckTools(s, client)
	registerMITRETools(s, client)
	registerActiveResponseTools(s, client)
	registerCDBTools(s, client)
}
