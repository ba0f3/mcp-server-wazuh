package wazuh

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

// noOpLogger is a logger that discards all log output
type noOpLogger struct{}

func (l *noOpLogger) Errorf(format string, v ...interface{}) {}
func (l *noOpLogger) Warnf(format string, v ...interface{})  {}
func (l *noOpLogger) Debugf(format string, v ...interface{}) {}

type Client struct {
	managerClient *resty.Client
	indexerClient *resty.Client
	token         string
	tokenExpiry   time.Time
	mu            sync.RWMutex
	username      string
	password      string
}

func NewClient(apiHost string, apiPort int, apiUsername, apiPassword string, indexerHost string, indexerPort int, indexerUsername, indexerPassword string, verifySSL bool) *Client {
	managerURL := formatURL(apiHost, apiPort)
	indexerURL := formatURL(indexerHost, indexerPort)

	noOpLog := &noOpLogger{}
	managerClient := resty.New().
		SetBaseURL(managerURL).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: !verifySSL}).
		SetLogger(noOpLog) // Suppress warnings in tests

	indexerClient := resty.New().
		SetBaseURL(indexerURL).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: !verifySSL}).
		SetBasicAuth(indexerUsername, indexerPassword).
		SetLogger(noOpLog) // Suppress warnings in tests

	return &Client{
		managerClient: managerClient,
		indexerClient: indexerClient,
		username:      apiUsername,
		password:      apiPassword,
	}
}

func formatURL(host string, port int) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		u, err := url.Parse(host)
		if err == nil && port > 0 {
			return fmt.Sprintf("%s://%s:%d%s", u.Scheme, u.Hostname(), port, u.Path)
		}
		return host
	}
	return fmt.Sprintf("https://%s:%d", host, port)
}

func (c *Client) authenticate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.username, c.password)))
	resp, err := c.managerClient.R().
		SetHeader("Authorization", "Basic "+auth).
		Get("/security/user/authenticate")

	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("authentication failed: %s", resp.String())
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return err
	}

	c.token = result.Data.Token
	// Wazuh tokens typically last 15-20 minutes. Let's assume 10 to be safe.
	c.tokenExpiry = time.Now().Add(10 * time.Minute)
	c.managerClient.SetAuthToken(c.token)

	return nil
}

func (c *Client) ManagerRequest() *resty.Request {
	if err := c.authenticate(); err != nil {
		// If auth fails, the request will likely fail too, but we return a request anyway.
	}
	return c.managerClient.R()
}

func (c *Client) IndexerRequest() *resty.Request {
	return c.indexerClient.R()
}
