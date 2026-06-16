// Package bloodhound provides a client for the BloodHound CE API.
//
// It handles authentication (password or token) and importing the AIHound
// extension schema and saved queries into a BloodHound CE instance.
package bloodhound

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Client is a simple HTTP client for BloodHound CE.
type Client struct {
	server     string
	token      string
	httpClient *http.Client
}

// NewClient creates a new BloodHound CE API client.
func NewClient(server string, verifySSL bool) *Client {
	// Strip trailing slash
	if len(server) > 0 && server[len(server)-1] == '/' {
		server = server[:len(server)-1]
	}

	transport := &http.Transport{}
	if !verifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-requested
	}

	return &Client{
		server:     server,
		httpClient: &http.Client{Transport: transport},
	}
}

func (c *Client) doRequest(method, path string, body interface{}) ([]byte, error) {
	url := c.server + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("BloodHound API error: HTTP %d %s: %s",
			resp.StatusCode, resp.Status, string(respBody))
	}

	return respBody, nil
}

// LoginPassword authenticates with username and password.
func (c *Client) LoginPassword(username, password string) error {
	payload := map[string]string{
		"login_method": "secret",
		"secret":       password,
		"username":     username,
	}
	respBody, err := c.doRequest("POST", "/api/v2/login", payload)
	if err != nil {
		return err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("parse login response: %w", err)
	}

	// Try top-level session_token, then data.session_token
	if token, ok := resp["session_token"].(string); ok && token != "" {
		c.token = token
		return nil
	}
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if token, ok := data["session_token"].(string); ok && token != "" {
			c.token = token
			return nil
		}
	}

	return fmt.Errorf("login failed — no session_token in response")
}

// LoginToken authenticates with API token ID and key.
func (c *Client) LoginToken(tokenID, tokenKey string) error {
	credentials := base64.StdEncoding.EncodeToString([]byte(tokenID + ":" + tokenKey))
	c.token = credentials

	// Verify it works
	if _, err := c.doRequest("GET", "/api/v2/self", nil); err != nil {
		return fmt.Errorf("token authentication failed — check token ID and key")
	}
	return nil
}

// RegisterSchema registers the AIHound OpenGraph extension schema.
func (c *Client) RegisterSchema(schema map[string]interface{}) error {
	_, err := c.doRequest("PUT", "/api/v2/extensions", schema)
	return err
}

// ImportQueries imports saved queries, skipping any that already exist by name.
// Returns (created, skipped, error).
func (c *Client) ImportQueries(queries []map[string]interface{}) (int, int, error) {
	// List existing queries
	respBody, err := c.doRequest("GET", "/api/v2/saved-queries", nil)
	if err != nil {
		return 0, 0, fmt.Errorf("list saved queries: %w", err)
	}

	var listResp struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &listResp); err != nil {
		return 0, 0, fmt.Errorf("parse saved queries: %w", err)
	}

	existingNames := make(map[string]bool)
	for _, q := range listResp.Data {
		existingNames[q.Name] = true
	}

	created, skipped := 0, 0
	for _, q := range queries {
		name, _ := q["name"].(string)
		if existingNames[name] {
			skipped++
			continue
		}
		query, _ := q["query"].(string)
		payload := map[string]string{
			"name":  name,
			"query": query,
		}
		if _, err := c.doRequest("POST", "/api/v2/saved-queries", payload); err != nil {
			return created, skipped, fmt.Errorf("create query %q: %w", name, err)
		}
		created++
	}

	return created, skipped, nil
}
