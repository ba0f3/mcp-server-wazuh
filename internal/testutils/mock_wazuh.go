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
		if r.URL.Path == "/agents" || r.URL.Path == "/agents/" {
			if scenario == "auth_error" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":   401,
					"message": "Invalid credentials",
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"affected_items": []interface{}{
						map[string]interface{}{
							"id":      "000",
							"name":    "Wazuh Manager",
							"status":  "active",
							"ip":      "127.0.0.1",
							"version": "4.12.0",
							"os": map[string]interface{}{
								"name":    "Linux",
								"version": "Ubuntu 22.04",
							},
						},
						map[string]interface{}{
							"id":      "001",
							"name":    "web-server-01",
							"status":  "active",
							"ip":      "192.168.1.100",
							"version": "4.12.0",
							"os": map[string]interface{}{
								"name":    "Linux",
								"version": "Ubuntu 22.04",
							},
						},
					},
				},
			})
			return
		}

		// Statistics endpoint
		if r.URL.Path == "/manager/stats" || r.URL.Path == "/manager/stats/" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"uptime": 3600,
					"cpu":    25.5,
					"memory": 45.2,
				},
			})
			return
		}

		// Rules summary endpoint
		if r.URL.Path == "/rules" || r.URL.Path == "/rules/" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"total_rules":  1500,
					"active_rules": 1200,
				},
			})
			return
		}

		// Cluster health endpoint
		if r.URL.Path == "/cluster/health" || r.URL.Path == "/cluster/health/" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"status": "healthy",
					"nodes":  3,
				},
			})
			return
		}

		// Cluster nodes endpoint
		if r.URL.Path == "/cluster/nodes" || r.URL.Path == "/cluster/nodes/" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"affected_items": []interface{}{
						map[string]interface{}{
							"name":   "node-1",
							"status": "active",
						},
					},
				},
			})
			return
		}

		// Connection validation endpoint
		if r.URL.Path == "/" && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"status": "connected",
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
