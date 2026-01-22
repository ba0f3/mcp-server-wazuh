package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds the application configuration
type Config struct {
	// Wazuh Manager API configuration
	WazuhAPIHost     string
	WazuhAPIPort     int
	WazuhAPIUsername string
	WazuhAPIPassword string

	// Wazuh Indexer API configuration
	WazuhIndexerHost     string
	WazuhIndexerPort     int
	WazuhIndexerUsername string
	WazuhIndexerPassword string

	// SSL configuration
	VerifySSL bool

	// MCP Server transport configuration
	Transport string
	Host      string
	Port      int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	_ = godotenv.Load()

	apiPort, _ := strconv.Atoi(getEnv("WAZUH_API_PORT", "55000"))
	indexerPort, _ := strconv.Atoi(getEnv("WAZUH_INDEXER_PORT", "9200"))
	serverPort, _ := strconv.Atoi(getEnv("MCP_SERVER_PORT", "8000"))

	return &Config{
		WazuhAPIHost:         getEnv("WAZUH_API_HOST", "localhost"),
		WazuhAPIPort:         apiPort,
		WazuhAPIUsername:     getEnv("WAZUH_API_USERNAME", "wazuh"),
		WazuhAPIPassword:     getEnv("WAZUH_API_PASSWORD", "wazuh"),
		WazuhIndexerHost:     getEnv("WAZUH_INDEXER_HOST", "localhost"),
		WazuhIndexerPort:     indexerPort,
		WazuhIndexerUsername: getEnv("WAZUH_INDEXER_USERNAME", "admin"),
		WazuhIndexerPassword: getEnv("WAZUH_INDEXER_PASSWORD", "admin"),
		VerifySSL:            getEnv("WAZUH_VERIFY_SSL", "false") == "true",
		Transport:            getEnv("MCP_SERVER_TRANSPORT", "stdio"),
		Host:                 getEnv("MCP_SERVER_HOST", "localhost"),
		Port:                 serverPort,
	}, nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
