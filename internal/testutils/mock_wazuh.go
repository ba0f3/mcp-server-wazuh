package testutils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
)

type MockWazuhServer struct {
	Server *httptest.Server
}

func NewMockWazuhServer(scenario string) *MockWazuhServer {
	mux := http.NewServeMux()

	// Default authentication endpoint
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if scenario == "auth_error" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid credentials",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"token": "mock.jwt.token",
			},
		})
	})

	// Alerts search endpoint
	alertRegex := regexp.MustCompile(`/wazuh-alerts.*/_search`)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if alertRegex.MatchString(r.URL.Path) {
			switch scenario {
			case "empty_alerts":
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"hits": map[string]interface{}{
						"hits": []interface{}{},
					},
				})
			case "alerts_error":
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "Internal server error",
				})
			case "malformed_alerts":
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"hits": map[string]interface{}{
						"hits": []interface{}{
							map[string]interface{}{
								"_source": map[string]interface{}{
									"id":        "missing_fields",
									"timestamp": "invalid-date-format",
								},
							},
							map[string]interface{}{
								"_source": map[string]interface{}{
									"id":        "partial_data",
									"timestamp": "2024-01-15T10:30:45.123Z",
									"rule": map[string]interface{}{
										"level": 5,
									},
									"agent": map[string]interface{}{
										"id": "001",
									},
								},
							},
						},
					},
				})
			default:
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(SampleAlertsResponse())
			}
			return
		}

		// Agents endpoint
		if r.URL.Path == "/agents" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"affected_items": []interface{}{
						map[string]interface{}{
							"id":     "000",
							"name":   "Wazuh Manager",
							"status": "active",
						},
					},
				},
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	})

	return &MockWazuhServer{
		Server: httptest.NewServer(mux),
	}
}

func (s *MockWazuhServer) Close() {
	s.Server.Close()
}

func (s *MockWazuhServer) URL() string {
	return s.Server.URL
}

func SampleAlertsResponse() map[string]interface{} {
	return map[string]interface{}{
		"hits": map[string]interface{}{
			"hits": []interface{}{
				map[string]interface{}{
					"_source": map[string]interface{}{
						"id":        "1747091815.1212763",
						"timestamp": "2024-01-15T10:30:45.123Z",
						"rule": map[string]interface{}{
							"level":       7,
							"description": "Attached USB Storage",
							"groups":      []string{"usb", "pci_dss"},
						},
						"agent": map[string]interface{}{
							"id":   "001",
							"name": "web-server-01",
						},
						"data": map[string]interface{}{
							"device":      "/dev/sdb1",
							"mount_point": "/media/usb",
						},
					},
				},
			},
		},
	}
}
