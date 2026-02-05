package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

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
	mux := http.NewServeMux()

	// MCP streamable HTTP handler at /mcp
	mcpHandler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return s.mcpServer
	}, nil)
	var mcpHTTPHandler http.Handler = mcpHandler
	if s.config.APIKey != "" {
		mcpHTTPHandler = s.apiKeyMiddleware(mcpHandler)
	}
	mux.Handle("/mcp", mcpHTTPHandler)

	// SSE handler at /sse
	var sseHandler http.Handler = http.HandlerFunc(s.handleSSE)
	if s.config.APIKey != "" {
		sseHandler = s.apiKeyMiddleware(http.HandlerFunc(s.handleSSE))
	}
	mux.Handle("/sse", sseHandler)
	// Serve SSE at root so clients that connect to the base URL (e.g. http://host:8000) get the endpoint event
	mux.HandleFunc("/", sseHandler.ServeHTTP)

	url := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	fmt.Fprintf(os.Stderr, "MCP server listening on %s\n", url)
	fmt.Fprintf(os.Stderr, "  - MCP (messages): http://%s/mcp\n", url)
	fmt.Fprintf(os.Stderr, "  - SSE (stream):  http://%s/sse or http://%s/\n", url, url)

	if err := http.ListenAndServe(url, mux); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}

// endpointURL returns the full URL for the message endpoint (where clients POST JSON-RPC) from the request.
func (s *Server) endpointURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = v
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, path)
}

// handleSSE handles Server-Sent Events connections.
// MCP clients expect the first SSE event to be "endpoint" with the URL they should use for sending messages (POST).
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Cache-Control")

	// Create a flusher to send data immediately
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// First event MUST be "endpoint" so MCP clients know where to POST messages (required for tool discovery etc.)
	endpointURL := s.endpointURL(r, "/mcp")
	fmt.Fprintf(w, "event: endpoint\n")
	fmt.Fprintf(w, "data: %s\n\n", endpointURL)
	flusher.Flush()

	// Keep connection alive and send periodic heartbeat
	ctx := r.Context()
	ticker := make(chan struct{})
	defer close(ticker)

	// Send heartbeat every 30 seconds
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker:
				return
			case <-time.After(30 * time.Second):
				fmt.Fprintf(w, ": heartbeat\n\n")
				flusher.Flush()
			}
		}
	}()

	// Wait for client disconnect
	<-ctx.Done()
}

// apiKeyMiddleware validates the API_KEY header for MCP server authentication
func (s *Server) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("API_KEY")
		if apiKey == "" {
			apiKey = r.Header.Get("X-API-Key") // Also check common alternative header
		}

		if apiKey == "" {
			apiKey = r.Header.Get("Authorization")
			apiKey = strings.TrimPrefix(apiKey, "Bearer ")
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
