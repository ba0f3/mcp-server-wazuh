package tools

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// getString safely extracts a string value from a map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// prettyJSON formats a value as indented JSON
func prettyJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// formatAgentID formats an agent ID to ensure it's a 3-digit string
func formatAgentID(id string) string {
	if n, err := strconv.Atoi(id); err == nil {
		if n <= 999 {
			return fmt.Sprintf("%03d", n)
		}
	}
	return id
}
