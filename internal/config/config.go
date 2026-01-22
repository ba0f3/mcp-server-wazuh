package config

import (
	"os"
	"path/filepath"
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
// Reads .env file from the current working directory or project root
func Load() (*Config, error) {
	// Get current working directory
	wd, err := os.Getwd()
	if err != nil {
		// If we can't get CWD, try loading from default location
		if loadErr := godotenv.Load(); loadErr != nil {
			// .env file is optional, so we continue even if it doesn't exist
		}
	} else {
		// Try loading from current working directory first
		envPath := filepath.Join(wd, ".env")
		if _, err := os.Stat(envPath); err == nil {
			// File exists in CWD, load it
			if loadErr := godotenv.Overload(envPath); loadErr != nil {
				// .env file exists but couldn't be loaded (might be permission issue)
			}
		} else {
			// .env not found in CWD, try project root (go up to find go.mod or .git)
			// Walk up the directory tree to find project root
			dir := wd
			for {
				envPath := filepath.Join(dir, ".env")
				if _, err := os.Stat(envPath); err == nil {
					// Found .env file
					if loadErr := godotenv.Overload(envPath); loadErr != nil {
						// .env file exists but couldn't be loaded
					}
					break
				}
				// Check if we're at project root (has go.mod or .git)
				if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
					// Found project root, but no .env here, try default search
					_ = godotenv.Overload()
					break
				}
				// Go up one directory
				parent := filepath.Dir(dir)
				if parent == dir {
					// Reached filesystem root, try default search
					_ = godotenv.Overload()
					break
				}
				dir = parent
			}
		}
	}

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
