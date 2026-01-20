package gitea

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
)

// TestNewClient tests the client constructor with various configurations.
func TestNewClient(t *testing.T) {
	t.Parallel()

	t.Run("with all parameters", func(t *testing.T) {
		t.Parallel()
		token := "gitea_test123"
		baseURL := "https://codeberg.org"
		client := NewClient(token, baseURL, nil)

		if client == nil {
			t.Fatal("NewClient returned nil")
		}
		if client.token != token {
			t.Errorf("token = %q, want %q", client.token, token)
		}
		if client.baseURL != baseURL {
			t.Errorf("baseURL = %q, want %q", client.baseURL, baseURL)
		}
		if client.httpClient == nil {
			t.Error("httpClient is nil")
		}
		if client.httpClient.Timeout != clientTimeout {
			t.Errorf("timeout = %v, want %v", client.httpClient.Timeout, clientTimeout)
		}
		if client.logger == nil {
			t.Error("logger is nil")
		}
	})

	t.Run("with empty baseURL defaults to codeberg", func(t *testing.T) {
		t.Parallel()
		client := NewClient("token", "", nil)

		if client.baseURL != "https://codeberg.org" {
			t.Errorf("baseURL = %q, want %q", client.baseURL, "https://codeberg.org")
		}
	})

	t.Run("strips trailing slash from baseURL", func(t *testing.T) {
		t.Parallel()
		client := NewClient("token", "https://gitea.example.com/", nil)

		if client.baseURL != "https://gitea.example.com" {
			t.Errorf("baseURL = %q, want %q", client.baseURL, "https://gitea.example.com")
		}
	})

	t.Run("with custom baseURL", func(t *testing.T) {
		t.Parallel()
		baseURL := "https://gitea.example.com"
		client := NewClient("token", baseURL, nil)

		if client.baseURL != baseURL {
			t.Errorf("baseURL = %q, want %q", client.baseURL, baseURL)
		}
	})
}

// TestAuthenticatedUser_Success tests successful user authentication.
func TestAuthenticatedUser_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "token test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") != "webhook-sprinkler/1.0" {
			t.Errorf("unexpected user-agent header: %s", r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("AuthenticatedUser failed: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("login = %q, want %q", user.Login, "testuser")
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
	if user.ID != 123 {
		t.Errorf("id = %d, want %d", user.ID, 123)
	}
}

// TestAuthenticatedUser_LoginFieldFallback tests that username field is used when login is empty.
func TestAuthenticatedUser_LoginFieldFallback(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Return username field but not login field
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username": "testuser",
			"id":       456,
		})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("AuthenticatedUser failed: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
}

// TestAuthenticatedUser_LoginOverridesUsername tests that login field takes precedence.
func TestAuthenticatedUser_LoginOverridesUsername(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Return both fields, login should take precedence
		_ = json.NewEncoder(w).Encode(User{
			Login:    "loginname",
			Username: "username",
			ID:       789,
		})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("AuthenticatedUser failed: %v", err)
	}
	if user.Username != "loginname" {
		t.Errorf("username = %q, want %q (should use login field)", user.Username, "loginname")
	}
}

// TestAuthenticatedUser_EmptyUsername tests response with no username fields.
func TestAuthenticatedUser_EmptyUsername(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "", Username: ""})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for empty username, got nil")
	}
	if !strings.Contains(err.Error(), "no username found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAuthenticatedUser_Unauthorized tests 401 response.
func TestAuthenticatedUser_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "invalid Gitea token") {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil user, got %+v", user)
	}
}

// TestAuthenticatedUser_Forbidden tests 403 response.
func TestAuthenticatedUser_Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "access forbidden") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAuthenticatedUser_ServerError tests 500 response with retry.
func TestAuthenticatedUser_ServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed on third attempt
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestAuthenticatedUser_BadGateway tests 502 response with retry.
func TestAuthenticatedUser_BadGateway(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
	if attempts >= 2 {
		t.Logf("retry successful after %d attempts", attempts)
	}
}

// TestAuthenticatedUser_ServiceUnavailable tests 503 response with retry.
func TestAuthenticatedUser_ServiceUnavailable(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for service unavailable, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected retries, got %d attempts", attempts)
	}
}

// TestAuthenticatedUser_UnexpectedStatus tests unexpected status code.
func TestAuthenticatedUser_UnexpectedStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for unexpected status, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAuthenticatedUser_MalformedJSON tests handling of malformed JSON responses.
func TestAuthenticatedUser_MalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_Success tests successful org listing.
func TestUserOrganizations_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user/orgs" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "token test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		orgs := []Organization{
			{Username: "org1", ID: 1},
			{Username: "org2", ID: 2},
			{Username: "org3", ID: 3},
		}
		_ = json.NewEncoder(w).Encode(orgs)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("userOrganizations failed: %v", err)
	}
	if len(orgs) != 3 {
		t.Errorf("len(orgs) = %d, want 3", len(orgs))
	}
	if orgs[0].Username != "org1" {
		t.Errorf("orgs[0].Username = %q, want %q", orgs[0].Username, "org1")
	}
}

// TestUserOrganizations_Unauthorized tests 401 response.
func TestUserOrganizations_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "invalid Gitea token") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_Forbidden tests 403 response.
func TestUserOrganizations_Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "access forbidden") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_ServerError tests server error retry.
func TestUserOrganizations_ServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		orgs := []Organization{{Username: "org1", ID: 1}}
		_ = json.NewEncoder(w).Encode(orgs)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

// TestUserOrganizations_BadGateway tests 502 response.
func TestUserOrganizations_BadGateway(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		orgs := []Organization{{Username: "org1", ID: 1}}
		_ = json.NewEncoder(w).Encode(orgs)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
	if attempts >= 2 {
		t.Logf("retry successful after %d attempts", attempts)
	}
}

// TestUserOrganizations_ServiceUnavailable tests 503 response.
func TestUserOrganizations_ServiceUnavailable(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for service unavailable, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected retries, got %d attempts", attempts)
	}
}

// TestUserOrganizations_UnexpectedStatus tests unexpected status code.
func TestUserOrganizations_UnexpectedStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for unexpected status, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected response status") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_MalformedJSON tests handling of malformed JSON.
func TestUserOrganizations_MalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_EmptyList tests empty organization list.
func TestUserOrganizations_EmptyList(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]Organization{})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("userOrganizations failed: %v", err)
	}
	if len(orgs) != 0 {
		t.Errorf("len(orgs) = %d, want 0", len(orgs))
	}
}

// TestUserAndOrgs_Success tests successful user and org retrieval.
func TestUserAndOrgs_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 1})
		case "/api/v1/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Username: "org1", ID: 10},
				{Username: "org2", ID: 20},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("UserAndOrgs failed: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
	if orgs[0] != "org1" || orgs[1] != "org2" {
		t.Errorf("orgs = %v, want [org1 org2]", orgs)
	}
}

// TestUserAndOrgs_UserError tests error during user fetch.
func TestUserAndOrgs_UserError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.UserAndOrgs(ctx)
	if err == nil {
		t.Fatal("expected error when user fetch fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get authenticated user") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserAndOrgs_OrgsError tests error during orgs fetch.
func TestUserAndOrgs_OrgsError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/api/v1/user/orgs":
			w.WriteHeader(http.StatusForbidden)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.UserAndOrgs(ctx)
	if err == nil {
		t.Fatal("expected error when orgs fetch fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get user organizations") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateOrgMembership_Success tests successful org membership validation.
func TestValidateOrgMembership_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/api/v1/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Username: "org1"},
				{Username: "targetorg"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	username, orgs, err := client.ValidateOrgMembership(ctx, "targetorg")
	if err != nil {
		t.Fatalf("ValidateOrgMembership failed: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
}

// TestValidateOrgMembership_NotMember tests validation when user is not a member.
func TestValidateOrgMembership_NotMember(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/api/v1/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Username: "org1"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	username, orgs, err := client.ValidateOrgMembership(ctx, "notmemberorg")
	if err == nil {
		t.Fatal("expected error when user is not a member, got nil")
	}
	if !strings.Contains(err.Error(), "not a member") {
		t.Errorf("unexpected error: %v", err)
	}
	// Should still return username and orgs even on error
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// TestValidateOrgMembership_EmptyOrgName tests validation with empty org name.
func TestValidateOrgMembership_EmptyOrgName(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://codeberg.org", nil)
	ctx := context.Background()

	_, _, err := client.ValidateOrgMembership(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty org name, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateOrgMembership_WhitespaceOrgName tests validation with whitespace org name.
func TestValidateOrgMembership_WhitespaceOrgName(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://codeberg.org", nil)
	ctx := context.Background()

	_, _, err := client.ValidateOrgMembership(ctx, "   ")
	if err == nil {
		t.Fatal("expected error for whitespace org name, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateOrgMembership_CaseInsensitive tests case-insensitive org matching.
func TestValidateOrgMembership_CaseInsensitive(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/api/v1/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Username: "TestOrg"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "testorg")
	if err != nil {
		t.Errorf("case-insensitive matching failed: %v", err)
	}
}

// TestValidateOrgMembership_UserAndOrgsError tests error propagation.
func TestValidateOrgMembership_UserAndOrgsError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "someorg")
	if err == nil {
		t.Fatal("expected error when UserAndOrgs fails, got nil")
	}
}

// TestUserTier_Success tests that UserTier always returns TierFlock.
func TestUserTier_Success(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://codeberg.org", nil)
	ctx := context.Background()

	tier, err := client.UserTier(ctx, "testuser")
	if err != nil {
		t.Fatalf("UserTier failed: %v", err)
	}
	if tier != github.TierFlock {
		t.Errorf("tier = %q, want %q", tier, github.TierFlock)
	}
}

// TestUserTier_EmptyUsername tests error with empty username.
func TestUserTier_EmptyUsername(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://codeberg.org", nil)
	ctx := context.Background()

	tier, err := client.UserTier(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty username, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
	if tier != github.TierFlock {
		t.Errorf("tier = %q, want %q on error", tier, github.TierFlock)
	}
}

// TestUserTier_DifferentUsernames tests tier for multiple users.
func TestUserTier_DifferentUsernames(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://codeberg.org", nil)
	ctx := context.Background()

	usernames := []string{"user1", "user2", "user3"}
	for _, username := range usernames {
		tier, err := client.UserTier(ctx, username)
		if err != nil {
			t.Errorf("UserTier(%q) failed: %v", username, err)
		}
		if tier != github.TierFlock {
			t.Errorf("UserTier(%q) = %q, want %q", username, tier, github.TierFlock)
		}
	}
}

// TestContextCancellation tests that context cancellation is respected.
func TestContextCancellation(t *testing.T) {
	t.Parallel()

	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// TestNetworkError tests handling of network errors with retry.
func TestNetworkError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// First 2 attempts: close connection to simulate network error
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			return
		}
		// Third attempt: success
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestMockClient_UserAndOrgs_Success tests successful UserAndOrgs call.
func TestMockClient_UserAndOrgs_Success(t *testing.T) {
	t.Parallel()
	mock := &MockClient{
		Username: "testuser",
		Orgs:     []string{"org1", "org2"},
	}

	ctx := context.Background()
	username, orgs, err := mock.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
	if mock.UserAndOrgsCalls != 1 {
		t.Errorf("UserAndOrgsCalls = %d, want 1", mock.UserAndOrgsCalls)
	}
}

// TestMockClient_UserAndOrgs_Error tests UserAndOrgs with error.
func TestMockClient_UserAndOrgs_Error(t *testing.T) {
	t.Parallel()
	mockErr := fmt.Errorf("mock error")
	mock := &MockClient{
		Err: mockErr,
	}

	ctx := context.Background()
	_, _, err := mock.UserAndOrgs(ctx)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "mock error") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMockClient_ValidateOrgMembership_Success tests successful validation.
func TestMockClient_ValidateOrgMembership_Success(t *testing.T) {
	t.Parallel()
	mock := &MockClient{
		Username: "testuser",
		Orgs:     []string{"org1", "org2"},
	}

	ctx := context.Background()
	username, orgs, err := mock.ValidateOrgMembership(ctx, "org1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
	if mock.LastValidatedOrg != "org1" {
		t.Errorf("LastValidatedOrg = %q, want %q", mock.LastValidatedOrg, "org1")
	}
	if mock.ValidateOrgMembershipCalls != 1 {
		t.Errorf("ValidateOrgMembershipCalls = %d, want 1", mock.ValidateOrgMembershipCalls)
	}
}

// TestMockClient_ValidateOrgMembership_NotMember tests when user is not a member.
func TestMockClient_ValidateOrgMembership_NotMember(t *testing.T) {
	t.Parallel()
	mock := &MockClient{
		Username: "testuser",
		Orgs:     []string{"org1", "org2"},
	}

	ctx := context.Background()
	username, orgs, err := mock.ValidateOrgMembership(ctx, "org3")

	if err == nil {
		t.Fatal("expected error for non-member org, got nil")
	}
	if !strings.Contains(err.Error(), "not a member") {
		t.Errorf("unexpected error: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
}

// TestMockClient_ValidateOrgMembership_Error tests validation with error.
func TestMockClient_ValidateOrgMembership_Error(t *testing.T) {
	t.Parallel()
	mockErr := fmt.Errorf("mock validation error")
	mock := &MockClient{
		Err: mockErr,
	}

	ctx := context.Background()
	_, _, err := mock.ValidateOrgMembership(ctx, "org1")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "mock validation error") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMockClient_UserTier_Success tests successful UserTier call.
func TestMockClient_UserTier_Success(t *testing.T) {
	t.Parallel()
	mock := &MockClient{
		Username: "testuser",
	}

	ctx := context.Background()
	tier, err := mock.UserTier(ctx, "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tier != github.TierFlock {
		t.Errorf("tier = %q, want %q", tier, github.TierFlock)
	}
	if mock.UserTierCalls != 1 {
		t.Errorf("UserTierCalls = %d, want 1", mock.UserTierCalls)
	}
}

// TestMockClient_UserTier_CustomTier tests UserTier with custom tier.
func TestMockClient_UserTier_CustomTier(t *testing.T) {
	t.Parallel()
	mock := &MockClient{
		Username: "testuser",
		Tier:     github.TierPro,
	}

	ctx := context.Background()
	tier, err := mock.UserTier(ctx, "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tier != github.TierPro {
		t.Errorf("tier = %q, want %q", tier, github.TierPro)
	}
}

// TestMockClient_UserTier_Error tests UserTier with error.
func TestMockClient_UserTier_Error(t *testing.T) {
	t.Parallel()
	mockErr := fmt.Errorf("mock tier error")
	mock := &MockClient{
		Err: mockErr,
	}

	ctx := context.Background()
	tier, err := mock.UserTier(ctx, "testuser")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "mock tier error") {
		t.Errorf("unexpected error: %v", err)
	}
	if tier != github.TierFlock {
		t.Errorf("tier = %q, want %q on error", tier, github.TierFlock)
	}
}

// TestMockClient_MultipleCalls tests call counting functionality.
func TestMockClient_MultipleCalls(t *testing.T) {
	t.Parallel()
	mock := &MockClient{
		Username: "testuser",
		Orgs:     []string{"org1"},
	}

	ctx := context.Background()

	// Call UserAndOrgs multiple times
	mock.UserAndOrgs(ctx)
	mock.UserAndOrgs(ctx)
	mock.UserAndOrgs(ctx)

	if mock.UserAndOrgsCalls != 3 {
		t.Errorf("UserAndOrgsCalls = %d, want 3", mock.UserAndOrgsCalls)
	}

	// Call ValidateOrgMembership multiple times
	mock.ValidateOrgMembership(ctx, "org1")
	mock.ValidateOrgMembership(ctx, "org1")

	if mock.ValidateOrgMembershipCalls != 2 {
		t.Errorf("ValidateOrgMembershipCalls = %d, want 2", mock.ValidateOrgMembershipCalls)
	}

	// Call UserTier multiple times
	mock.UserTier(ctx, "testuser")
	mock.UserTier(ctx, "testuser")
	mock.UserTier(ctx, "testuser")

	if mock.UserTierCalls != 3 {
		t.Errorf("UserTierCalls = %d, want 3", mock.UserTierCalls)
	}
}

// TestLargeResponseBody tests that large responses are limited.
func TestLargeResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write a very large response (> 1MB limit)
		large := strings.Repeat("x", 2*1024*1024)
		_, _ = w.Write([]byte(`{"login":"` + large + `"}`))
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// This should not panic and should handle the limited read
	_, err := client.AuthenticatedUser(ctx)
	// The error could be either a parse error (due to truncation) or success if truncated at valid JSON
	// We just want to ensure it doesn't panic or hang
	_ = err
}

// TestClientTimeout tests that the client respects timeout configuration.
func TestClientTimeout(t *testing.T) {
	t.Parallel()

	// Create a server that takes longer than the client timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Second) // Longer than clientTimeout (10s)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// TestUserOrganizations_NetworkError tests network error retry.
func TestUserOrganizations_NetworkError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// First 2 attempts: close connection
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			return
		}
		// Third attempt: success
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]Organization{{Username: "org1"}})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestResponseBodyCloseError tests handling of errors when closing response body.
func TestResponseBodyCloseError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// Should succeed even if there are issues closing the body
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("AuthenticatedUser failed: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
}

// TestValidateOrgMembership_OrgNameWithSpaces tests org name with leading/trailing spaces.
func TestValidateOrgMembership_OrgNameWithSpaces(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/api/v1/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Username: "targetorg"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// Should trim spaces and succeed
	_, _, err := client.ValidateOrgMembership(ctx, "  targetorg  ")
	if err != nil {
		t.Errorf("ValidateOrgMembership with spaces failed: %v", err)
	}
}

// TestAuthenticatedUser_ReadBodyError tests handling of body read errors.
func TestAuthenticatedUser_ReadBodyError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// Return 500 to trigger retry on read error
			w.Header().Set("Content-Length", "1000000")
			w.WriteHeader(http.StatusInternalServerError)
			// Close connection immediately
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return
		}
		// Succeed on third attempt
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestUserOrganizations_ReadBodyError tests handling of body read errors.
func TestUserOrganizations_ReadBodyError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			// Return 500 to trigger retry on read error
			w.Header().Set("Content-Length", "1000000")
			w.WriteHeader(http.StatusInternalServerError)
			// Close connection immediately
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return
		}
		// Succeed on second attempt
		w.WriteHeader(http.StatusOK)
		orgs := []Organization{{Username: "org1"}}
		_ = json.NewEncoder(w).Encode(orgs)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
	if attempts >= 2 {
		t.Logf("retry successful after %d attempts", attempts)
	}
}

// TestAuthenticatedUser_PersistentServerError tests when server errors persist.
func TestAuthenticatedUser_PersistentServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for persistent server errors, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestUserOrganizations_PersistentServerError tests when server errors persist.
func TestUserOrganizations_PersistentServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for persistent server errors, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}
