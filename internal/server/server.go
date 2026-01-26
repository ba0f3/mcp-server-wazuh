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
		Version: "0.5.0",
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
	mcpHandler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return s.mcpServer
	}, nil)

	// Wrap handler with API key authentication middleware
	var handler http.Handler = mcpHandler
	if s.config.APIKey != "" {
		handler = s.apiKeyMiddleware(mcpHandler)
	}

	url := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	fmt.Fprintf(os.Stderr, "MCP server listening on %s\n", url)

	if err := http.ListenAndServe(url, handler); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}

// apiKeyMiddleware validates the API_KEY header for MCP server authentication
func (s *Server) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("API_KEY")
		if apiKey == "" {
			apiKey = r.Header.Get("X-API-Key") // Also check common alternative header
		}

		if s.config.APIKey != "" && apiKey != s.config.APIKey {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"error":"unauthorized","message":"Invalid or missing API_KEY header"}`)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// runStdio starts the server with stdio transport
func (s *Server) runStdio() error {
	if err := s.mcpServer.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
