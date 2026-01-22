package wazuh

// This file previously contained security-related functions that used non-existent Wazuh API endpoints.
// These functions have been removed as they were calling endpoints that don't exist in the standard Wazuh API.
// For security analysis, use the alert search tools which query the Wazuh Indexer API (valid endpoint).
