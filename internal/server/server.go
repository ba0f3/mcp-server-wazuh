package server

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/ba0f3/mcp-server-wazuh/internal/config"
	"github.com/ba0f3/mcp-server-wazuh/internal/tools"
	"github.com/ba0f3/mcp-server-wazuh/internal/wazuh"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server represents the MCP server instance
type Server struct {
	mcpServer *mcp.Server
	client    *wazuh.Client
	config    *config.Config
}

// New creates a new MCP server instance
func New(cfg *config.Config) (*Server, error) {
	client := wazuh.NewClient(
		cfg.WazuhAPIHost,
		cfg.WazuhAPIPort,
		cfg.WazuhAPIUsername,
		cfg.WazuhAPIPassword,
		cfg.WazuhIndexerHost,
		cfg.WazuhIndexerPort,
		cfg.WazuhIndexerUsername,
		cfg.WazuhIndexerPassword,
		cfg.VerifySSL,
	)

	s := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-server-wazuh",
		Version: "0.4.0",
	}, nil)

	tools.RegisterTools(s, client)

	return &Server{
		mcpServer: s,
		client:    client,
		config:    cfg,
	}, nil
}

// Run starts the server with the configured transport
func (s *Server) Run() error {
	if s.config.Transport == "http" {
		return s.runHTTP()
	}
	return s.runStdio()
}

// runHTTP starts the server with HTTP transport
func (s *Server) runHTTP() error {
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return s.mcpServer
	}, nil)

	url := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	fmt.Fprintf(os.Stderr, "MCP server listening on %s\n", url)

	if err := http.ListenAndServe(url, handler); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}

// runStdio starts the server with stdio transport
func (s *Server) runStdio() error {
	if err := s.mcpServer.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
