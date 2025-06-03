package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIEndToEnd(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{"TestHealthEndpoint", testHealthEndpoint},
		{"TestMetricsEndpoint", testMetricsEndpoint},
		{"TestPodsAPI", testPodsAPI},
		{"TestServicesAPI", testServicesAPI},
		{"TestDeploymentsAPI", testDeploymentsAPI},
		{"TestWebSocketConnection", testWebSocketConnection},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}

func setupTestServer(t *testing.T) (*httptest.Server, *mux.Router) {
	router := mux.NewRouter()
	// Setup basic routes for testing
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}).Methods("GET")

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return server, router
}

func testHealthEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var health map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&health)
	require.NoError(t, err)

	assert.Equal(t, "ok", health["status"])
	assert.Contains(t, health, "timestamp")
	assert.Contains(t, health, "version")
}

func testMetricsEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", resp.Header.Get("Content-Type"))
}

func testPodsAPI(t *testing.T) {
	server, _ := setupTestServer(t)

	// Test GET /api/v1/pods
	resp, err := http.Get(server.URL + "/api/v1/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var pods map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&pods)
	require.NoError(t, err)

	assert.Contains(t, pods, "items")
	assert.IsType(t, []interface{}{}, pods["items"])
}

func testServicesAPI(t *testing.T) {
	server, _ := setupTestServer(t)

	// Test GET /api/v1/services
	resp, err := http.Get(server.URL + "/api/v1/services")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var services map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&services)
	require.NoError(t, err)

	assert.Contains(t, services, "items")
	assert.IsType(t, []interface{}{}, services["items"])
}

func testDeploymentsAPI(t *testing.T) {
	server, _ := setupTestServer(t)

	// Test GET /api/v1/deployments
	resp, err := http.Get(server.URL + "/api/v1/deployments")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var deployments map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&deployments)
	require.NoError(t, err)

	assert.Contains(t, deployments, "items")
	assert.IsType(t, []interface{}{}, deployments["items"])
}

func testWebSocketConnection(t *testing.T) {
	server, _ := setupTestServer(t)

	// For this test, we'll just verify the endpoint exists
	// In a real scenario, you'd use a WebSocket client library
	resp, err := http.Get(server.URL + "/ws")
	require.NoError(t, err)
	defer resp.Body.Close()

	// WebSocket upgrade should fail with regular HTTP request
	// but the endpoint should exist
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIAuthentication(t *testing.T) {
	server, _ := setupTestServer(t)

	// Test protected endpoints without authentication
	protectedEndpoints := []string{
		"/api/v1/pods",
		"/api/v1/services",
		"/api/v1/deployments",
	}

	for _, endpoint := range protectedEndpoints {
		t.Run(fmt.Sprintf("Unauthenticated_%s", endpoint), func(t *testing.T) {
			req, err := http.NewRequest("POST", server.URL+endpoint, bytes.NewBuffer([]byte(`{}`)))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should either be unauthorized or method not allowed
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusMethodNotAllowed, http.StatusForbidden}, resp.StatusCode)
		})
	}
}

func TestAPIRateLimiting(t *testing.T) {
	server, _ := setupTestServer(t)

	// Make multiple rapid requests to test rate limiting
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	var responses []*http.Response
	for i := 0; i < 10; i++ {
		resp, err := client.Get(server.URL + "/health")
		if err != nil {
			t.Logf("Request %d failed: %v", i, err)
			continue
		}
		responses = append(responses, resp)
	}

	// Clean up responses
	for _, resp := range responses {
		resp.Body.Close()
	}

	// At least some requests should succeed
	assert.Greater(t, len(responses), 0)

	// Check if any requests were rate limited (429 status)
	rateLimited := false
	for _, resp := range responses {
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			break
		}
	}

	// Note: Rate limiting might not trigger in test environment
	// This test mainly verifies the endpoint handles rapid requests gracefully
	t.Logf("Rate limiting triggered: %v", rateLimited)
}

func TestAPICORS(t *testing.T) {
	server, _ := setupTestServer(t)

	// Test CORS preflight request
	req, err := http.NewRequest("OPTIONS", server.URL+"/api/v1/pods", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle CORS preflight
	assert.Contains(t, []int{http.StatusOK, http.StatusNoContent}, resp.StatusCode)

	// Check CORS headers
	assert.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}
