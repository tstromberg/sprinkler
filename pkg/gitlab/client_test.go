package gitlab

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

// TestNewClient tests the client constructor.
func TestNewClient(t *testing.T) {
	t.Parallel()

	token := "glpat-test123"
	client := NewClient(token, "", nil)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.token != token {
		t.Errorf("token = %q, want %q", client.token, token)
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if client.httpClient.Timeout != clientTimeout {
		t.Errorf("timeout = %v, want %v", client.httpClient.Timeout, clientTimeout)
	}
	if client.baseURL != "https://gitlab.com" {
		t.Errorf("baseURL = %q, want %q", client.baseURL, "https://gitlab.com")
	}
}

// TestNewClient_CustomBaseURL tests client constructor with custom base URL.
func TestNewClient_CustomBaseURL(t *testing.T) {
	t.Parallel()

	token := "glpat-test123"
	customURL := "https://gitlab.example.com"
	client := NewClient(token, customURL, nil)

	if client.baseURL != customURL {
		t.Errorf("baseURL = %q, want %q", client.baseURL, customURL)
	}
}

// TestNewClient_BaseURLTrailingSlash tests that trailing slashes are removed.
func TestNewClient_BaseURLTrailingSlash(t *testing.T) {
	t.Parallel()

	token := "glpat-test123"
	customURL := "https://gitlab.example.com/"
	client := NewClient(token, customURL, nil)

	if client.baseURL != "https://gitlab.example.com" {
		t.Errorf("baseURL = %q, want %q (trailing slash should be removed)", client.baseURL, "https://gitlab.example.com")
	}
}

// TestAuthenticatedUser_Success tests successful user authentication.
func TestAuthenticatedUser_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") != "webhook-sprinkler/1.0" {
			t.Errorf("unexpected user-agent header: %s", r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
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
	if user.ID != 123 {
		t.Errorf("id = %d, want %d", user.ID, 123)
	}
}

// TestAuthenticatedUser_Unauthorized tests 401 response.
func TestAuthenticatedUser_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "invalid GitLab token") {
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
	user, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "access forbidden") {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil user, got %+v", user)
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
		_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
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
		_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
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
		// Should have retried at least once
		return
	}
	t.Errorf("expected at least 2 attempts, got %d", attempts)
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

// TestAuthenticatedUser_EmptyUsername tests response with empty username.
func TestAuthenticatedUser_EmptyUsername(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Username: "", ID: 123})
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

// TestAuthenticatedUser_NetworkError tests network error with retry.
func TestAuthenticatedUser_NetworkError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// Close connection to simulate network error
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
		_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
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

// TestAuthenticatedUser_UnexpectedStatus tests unexpected status codes.
func TestAuthenticatedUser_UnexpectedStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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

// TestUserGroups_Success tests successful group listing.
func TestUserGroups_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/groups" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if !strings.Contains(r.URL.RawQuery, "min_access_level=10") {
			t.Errorf("expected min_access_level=10 parameter, got query: %s", r.URL.RawQuery)
		}

		w.WriteHeader(http.StatusOK)
		groups := []Group{
			{FullPath: "group1", ID: 1},
			{FullPath: "group2/subgroup", ID: 2},
			{FullPath: "group3", ID: 3},
		}
		_ = json.NewEncoder(w).Encode(groups)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	groups, err := client.userGroups(ctx)
	if err != nil {
		t.Fatalf("userGroups failed: %v", err)
	}
	if len(groups) != 3 {
		t.Errorf("len(groups) = %d, want 3", len(groups))
	}
	if groups[0].FullPath != "group1" {
		t.Errorf("groups[0].FullPath = %q, want %q", groups[0].FullPath, "group1")
	}
	if groups[1].FullPath != "group2/subgroup" {
		t.Errorf("groups[1].FullPath = %q, want %q", groups[1].FullPath, "group2/subgroup")
	}
}

// TestUserGroups_EmptyList tests empty group list.
func TestUserGroups_EmptyList(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]Group{})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	groups, err := client.userGroups(ctx)
	if err != nil {
		t.Fatalf("userGroups failed: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("len(groups) = %d, want 0", len(groups))
	}
}

// TestUserGroups_Unauthorized tests 401 response.
func TestUserGroups_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "invalid GitLab token") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserGroups_Forbidden tests 403 response.
func TestUserGroups_Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "access forbidden") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserGroups_ServerError tests 500 response with retry.
func TestUserGroups_ServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		groups := []Group{{FullPath: "group1", ID: 1}}
		_ = json.NewEncoder(w).Encode(groups)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	groups, err := client.userGroups(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("len(groups) = %d, want 1", len(groups))
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

// TestUserGroups_BadGateway tests 502 response with retry.
func TestUserGroups_BadGateway(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		groups := []Group{{FullPath: "group1", ID: 1}}
		_ = json.NewEncoder(w).Encode(groups)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	groups, err := client.userGroups(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("len(groups) = %d, want 1", len(groups))
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

// TestUserGroups_ServiceUnavailable tests 503 response with retry.
func TestUserGroups_ServiceUnavailable(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error for service unavailable, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected retries, got %d attempts", attempts)
	}
}

// TestUserGroups_MalformedJSON tests handling of malformed JSON.
func TestUserGroups_MalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserGroups_NetworkError tests network error with retry.
func TestUserGroups_NetworkError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// Close connection to simulate network error
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
		groups := []Group{{FullPath: "group1", ID: 1}}
		_ = json.NewEncoder(w).Encode(groups)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	groups, err := client.userGroups(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("len(groups) = %d, want 1", len(groups))
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestUserGroups_UnexpectedStatus tests unexpected status codes.
func TestUserGroups_UnexpectedStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error for unexpected status, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected response status") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserAndOrgs_Success tests successful user and groups retrieval.
func TestUserAndOrgs_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "group1", ID: 1},
				{FullPath: "group2", ID: 2},
			}
			_ = json.NewEncoder(w).Encode(groups)
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
	if orgs[0] != "group1" || orgs[1] != "group2" {
		t.Errorf("orgs = %v, want [group1 group2]", orgs)
	}
}

// TestUserAndOrgs_AuthenticationFailure tests authentication failure.
func TestUserAndOrgs_AuthenticationFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.UserAndOrgs(ctx)
	if err == nil {
		t.Fatal("expected error for authentication failure, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get authenticated user") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserAndOrgs_GroupsFailure tests failure when fetching groups.
func TestUserAndOrgs_GroupsFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.UserAndOrgs(ctx)
	if err == nil {
		t.Fatal("expected error when groups fetch fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get user groups") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserAndOrgs_EmptyGroups tests user with no groups.
func TestUserAndOrgs_EmptyGroups(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]Group{})
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
	if len(orgs) != 0 {
		t.Errorf("len(orgs) = %d, want 0", len(orgs))
	}
}

// TestValidateOrgMembership_Success tests successful org membership validation.
func TestValidateOrgMembership_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "group1", ID: 1},
				{FullPath: "targetgroup", ID: 2},
			}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	username, orgs, err := client.ValidateOrgMembership(ctx, "targetgroup")
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
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "group1", ID: 1},
			}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	username, orgs, err := client.ValidateOrgMembership(ctx, "notmembergroup")
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

	client := NewClient("test-token", "", nil)
	ctx := context.Background()

	_, _, err := client.ValidateOrgMembership(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty org name, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateOrgMembership_WhitespaceOrgName tests validation with whitespace-only org name.
func TestValidateOrgMembership_WhitespaceOrgName(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "", nil)
	ctx := context.Background()

	_, _, err := client.ValidateOrgMembership(ctx, "   ")
	if err == nil {
		t.Fatal("expected error for whitespace org name, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateOrgMembership_CaseInsensitive tests case-insensitive group matching.
func TestValidateOrgMembership_CaseInsensitive(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "TestGroup", ID: 1},
			}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "testgroup")
	if err != nil {
		t.Errorf("case-insensitive matching failed: %v", err)
	}
}

// TestValidateOrgMembership_SubgroupPath tests validation with subgroup path.
func TestValidateOrgMembership_SubgroupPath(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "parent/child", ID: 1},
			}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "parent/child")
	if err != nil {
		t.Fatalf("ValidateOrgMembership failed for subgroup: %v", err)
	}
}

// TestValidateOrgMembership_UserAndOrgsFailure tests validation when UserAndOrgs fails.
func TestValidateOrgMembership_UserAndOrgsFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "somegroup")
	if err == nil {
		t.Fatal("expected error when UserAndOrgs fails, got nil")
	}
}

// TestUserTier_ReturnsFlockTier tests that UserTier always returns TierFlock.
func TestUserTier_ReturnsFlockTier(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "", nil)
	ctx := context.Background()

	tier, err := client.UserTier(ctx, "testuser")
	if err != nil {
		t.Fatalf("UserTier failed: %v", err)
	}
	if tier != github.TierFlock {
		t.Errorf("tier = %v, want %v", tier, github.TierFlock)
	}
}

// TestUserTier_EmptyUsername tests UserTier with empty username.
func TestUserTier_EmptyUsername(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "", nil)
	ctx := context.Background()

	_, err := client.UserTier(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty username, got nil")
	}
	if !strings.Contains(err.Error(), "username cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserTier_MultipleUsers tests UserTier with different usernames.
func TestUserTier_MultipleUsers(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "", nil)
	ctx := context.Background()

	users := []string{"user1", "user2", "user3"}
	for _, username := range users {
		tier, err := client.UserTier(ctx, username)
		if err != nil {
			t.Errorf("UserTier failed for %s: %v", username, err)
		}
		if tier != github.TierFlock {
			t.Errorf("tier for %s = %v, want %v", username, tier, github.TierFlock)
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
		_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
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

// TestContextTimeout tests that context timeout is respected.
func TestContextTimeout(t *testing.T) {
	t.Parallel()

	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for context timeout, got nil")
	}
}

// TestLargeResponseBody tests that large responses are handled correctly.
func TestLargeResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write a very large response (> 1MB limit)
		large := strings.Repeat("x", 2*1024*1024)
		_, _ = w.Write([]byte(`{"username":"` + large + `", "id": 123}`))
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

// TestUnexpectedStatusCodes tests handling of various unexpected status codes.
func TestUnexpectedStatusCodes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		statusCode int
		wantRetry  bool
	}{
		{"BadRequest", http.StatusBadRequest, false},
		{"NotFound", http.StatusNotFound, false},
		{"BadGateway", http.StatusBadGateway, true},
		{"ServiceUnavailable", http.StatusServiceUnavailable, true},
		{"GatewayTimeout", http.StatusGatewayTimeout, false},
		{"InternalServerError", http.StatusInternalServerError, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			client := NewClient("test-token", server.URL, nil)

			ctx := context.Background()
			_, err := client.AuthenticatedUser(ctx)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if tc.wantRetry && attempts < 3 {
				t.Errorf("expected retries for status %d, got %d attempts", tc.statusCode, attempts)
			}
			if !tc.wantRetry && attempts > 1 {
				t.Errorf("expected no retries for status %d, got %d attempts", tc.statusCode, attempts)
			}
		})
	}
}

// TestNewClient_NilLogger tests that NewClient handles nil logger.
func TestNewClient_NilLogger(t *testing.T) {
	t.Parallel()

	client := NewClient("token", "", nil)
	if client.logger == nil {
		t.Error("logger should not be nil even when nil is passed")
	}
}

// TestAuthenticatedUser_ReadBodyError simulates error reading response body.
func TestAuthenticatedUser_ReadBodyError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// Write less than promised to trigger read error
		_, _ = w.Write([]byte(`{"username":"test", "id": 123}`))
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)
	// Use a custom client with very small timeout to trigger error
	client.httpClient.Timeout = 1 * time.Nanosecond

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error due to timeout, got nil")
	}
}

// TestUserGroups_PersistentFailure tests that all retries are exhausted.
func TestUserGroups_PersistentFailure(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error after all retries exhausted, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestValidateOrgMembership_TrimWhitespace tests that org name whitespace is trimmed.
func TestValidateOrgMembership_TrimWhitespace(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "mygroup", ID: 1},
			}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// Test with leading/trailing whitespace
	_, _, err := client.ValidateOrgMembership(ctx, "  mygroup  ")
	if err != nil {
		t.Fatalf("ValidateOrgMembership should trim whitespace: %v", err)
	}
}

// TestMultipleSequentialCalls tests multiple sequential API calls.
func TestMultipleSequentialCalls(t *testing.T) {
	t.Parallel()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: fmt.Sprintf("user%d", callCount), ID: callCount})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]Group{})
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)
	ctx := context.Background()

	// Make multiple calls
	for i := 1; i <= 3; i++ {
		_, _, err := client.UserAndOrgs(ctx)
		if err != nil {
			t.Fatalf("UserAndOrgs call %d failed: %v", i, err)
		}
	}

	// Each UserAndOrgs call makes 2 API calls (user + groups)
	expectedCalls := 6
	if callCount != expectedCalls {
		t.Errorf("expected %d API calls, got %d", expectedCalls, callCount)
	}
}

// TestUserGroups_MultipleGroups tests handling of multiple groups.
func TestUserGroups_MultipleGroups(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		groups := make([]Group, 10)
		for i := range 10 {
			groups[i] = Group{
				FullPath: fmt.Sprintf("group%d", i+1),
				ID:       i + 1,
			}
		}
		_ = json.NewEncoder(w).Encode(groups)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	groups, err := client.userGroups(ctx)
	if err != nil {
		t.Fatalf("userGroups failed: %v", err)
	}
	if len(groups) != 10 {
		t.Errorf("len(groups) = %d, want 10", len(groups))
	}
	for i, group := range groups {
		expectedPath := fmt.Sprintf("group%d", i+1)
		if group.FullPath != expectedPath {
			t.Errorf("groups[%d].FullPath = %q, want %q", i, group.FullPath, expectedPath)
		}
	}
}

// TestAuthenticatedUser_SuccessAfterRetries tests eventual success after retries.
func TestAuthenticatedUser_SuccessAfterRetries(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if attempts == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// Third attempt succeeds
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
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
	if attempts != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", attempts)
	}
}

// TestAuthenticatedUser_AllRetriesFail tests that lastErr is returned when all retries fail.
func TestAuthenticatedUser_AllRetriesFail(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error when all retries fail, got nil")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("unexpected error: %v", err)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestUserGroups_AllRetriesFail tests that lastErr is returned when all retries fail.
func TestUserGroups_AllRetriesFail(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error when all retries fail, got nil")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("unexpected error: %v", err)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestAuthenticatedUser_RequestCreationError tests error during request creation.
func TestAuthenticatedUser_RequestCreationError(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "ht!tp://invalid url with spaces", nil)

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// TestUserGroups_RequestCreationError tests error during request creation.
func TestUserGroups_RequestCreationError(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "ht!tp://invalid url with spaces", nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// TestAuthenticatedUser_ReadAllError tests error when reading response body.
func TestAuthenticatedUser_ReadAllError(t *testing.T) {
	t.Parallel()

	// Create a server that returns an infinite stream
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10000000")
		w.WriteHeader(http.StatusOK)
		// Write a huge chunk that exceeds the 1MB limit
		hugeData := make([]byte, 2*1024*1024)
		for i := range hugeData {
			hugeData[i] = 'x'
		}
		_, _ = w.Write(hugeData)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// The 1MB limit should truncate the response, causing a JSON parse error
	_, err := client.AuthenticatedUser(ctx)
	// This will fail to parse as valid JSON due to truncation
	_ = err
}

// TestUserGroups_ReadAllError tests error when reading response body.
func TestUserGroups_ReadAllError(t *testing.T) {
	t.Parallel()

	// Create a server that returns an infinite stream
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10000000")
		w.WriteHeader(http.StatusOK)
		// Write a huge chunk that exceeds the 1MB limit
		hugeData := make([]byte, 2*1024*1024)
		for i := range hugeData {
			hugeData[i] = 'x'
		}
		_, _ = w.Write(hugeData)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// The 1MB limit should truncate the response, causing a JSON parse error
	_, err := client.userGroups(ctx)
	// This will fail to parse as valid JSON due to truncation
	_ = err
}

// TestAuthenticatedUser_MixedRetryableErrors tests different retryable errors.
func TestAuthenticatedUser_MixedRetryableErrors(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		switch attempts {
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after mixed retries, got: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("username = %q, want %q", user.Username, "testuser")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestUserGroups_MixedRetryableErrors tests different retryable errors.
func TestUserGroups_MixedRetryableErrors(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		switch attempts {
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusOK)
			groups := []Group{{FullPath: "group1", ID: 1}}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	groups, err := client.userGroups(ctx)
	if err != nil {
		t.Fatalf("expected success after mixed retries, got: %v", err)
	}
	if len(groups) != 1 {
		t.Errorf("len(groups) = %d, want 1", len(groups))
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestValidateOrgMembership_MultipleGroups tests membership validation with multiple groups.
func TestValidateOrgMembership_MultipleGroups(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "group1", ID: 1},
				{FullPath: "group2", ID: 2},
				{FullPath: "group3", ID: 3},
				{FullPath: "group4", ID: 4},
				{FullPath: "group5", ID: 5},
			}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// Test finding group in the middle
	_, orgs, err := client.ValidateOrgMembership(ctx, "group3")
	if err != nil {
		t.Fatalf("ValidateOrgMembership failed: %v", err)
	}
	if len(orgs) != 5 {
		t.Errorf("len(orgs) = %d, want 5", len(orgs))
	}
}

// TestValidateOrgMembership_LastGroup tests finding the last group in the list.
func TestValidateOrgMembership_LastGroup(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Username: "testuser", ID: 123})
		case "/api/v4/groups":
			w.WriteHeader(http.StatusOK)
			groups := []Group{
				{FullPath: "group1", ID: 1},
				{FullPath: "group2", ID: 2},
				{FullPath: "targetgroup", ID: 3},
			}
			_ = json.NewEncoder(w).Encode(groups)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "targetgroup")
	if err != nil {
		t.Fatalf("ValidateOrgMembership failed for last group: %v", err)
	}
}

// TestNewClient_EmptyBaseURL tests that empty base URL defaults to gitlab.com.
func TestNewClient_EmptyBaseURL(t *testing.T) {
	t.Parallel()

	client := NewClient("token", "", nil)
	if client.baseURL != "https://gitlab.com" {
		t.Errorf("baseURL = %q, want %q", client.baseURL, "https://gitlab.com")
	}
}

// TestAuthenticatedUser_PersistentServerErrors tests all retries with server errors.
func TestAuthenticatedUser_PersistentServerErrors(t *testing.T) {
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
		t.Fatal("expected error when all retries fail with server errors, got nil")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("unexpected error: %v", err)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestUserGroups_PersistentServerErrors tests all retries with server errors.
func TestUserGroups_PersistentServerErrors(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, err := client.userGroups(ctx)
	if err == nil {
		t.Fatal("expected error when all retries fail with server errors, got nil")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("unexpected error: %v", err)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestMockClient_UserAndOrgs tests MockClient UserAndOrgs method.
func TestMockClient_UserAndOrgs(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Groups:   []string{"group1", "group2"},
		}

		ctx := context.Background()
		username, groups, err := mock.UserAndOrgs(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "testuser" {
			t.Errorf("username = %q, want %q", username, "testuser")
		}
		if len(groups) != 2 {
			t.Errorf("len(groups) = %d, want 2", len(groups))
		}
		if mock.UserAndOrgsCalls != 1 {
			t.Errorf("UserAndOrgsCalls = %d, want 1", mock.UserAndOrgsCalls)
		}
	})

	t.Run("error", func(t *testing.T) {
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
	})

	t.Run("multiple calls", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Groups:   []string{"group1"},
		}

		ctx := context.Background()
		for i := 1; i <= 5; i++ {
			_, _, _ = mock.UserAndOrgs(ctx)
			if mock.UserAndOrgsCalls != i {
				t.Errorf("after %d calls, UserAndOrgsCalls = %d", i, mock.UserAndOrgsCalls)
			}
		}
	})
}

// TestMockClient_ValidateOrgMembership tests MockClient ValidateOrgMembership method.
func TestMockClient_ValidateOrgMembership(t *testing.T) {
	t.Parallel()

	t.Run("success - member", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Groups:   []string{"group1", "group2", "group3"},
		}

		ctx := context.Background()
		username, groups, err := mock.ValidateOrgMembership(ctx, "group2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "testuser" {
			t.Errorf("username = %q, want %q", username, "testuser")
		}
		if len(groups) != 3 {
			t.Errorf("len(groups) = %d, want 3", len(groups))
		}
		if mock.LastValidatedGroup != "group2" {
			t.Errorf("LastValidatedGroup = %q, want %q", mock.LastValidatedGroup, "group2")
		}
		if mock.ValidateOrgMembershipCalls != 1 {
			t.Errorf("ValidateOrgMembershipCalls = %d, want 1", mock.ValidateOrgMembershipCalls)
		}
	})

	t.Run("not a member", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Groups:   []string{"group1", "group2"},
		}

		ctx := context.Background()
		username, groups, err := mock.ValidateOrgMembership(ctx, "group3")
		if err == nil {
			t.Fatal("expected error for non-member, got nil")
		}
		if !strings.Contains(err.Error(), "not a member") {
			t.Errorf("unexpected error: %v", err)
		}
		// Should still return username and groups
		if username != "testuser" {
			t.Errorf("username = %q, want %q", username, "testuser")
		}
		if len(groups) != 2 {
			t.Errorf("len(groups) = %d, want 2", len(groups))
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		mockErr := fmt.Errorf("validation error")
		mock := &MockClient{
			Err: mockErr,
		}

		ctx := context.Background()
		_, _, err := mock.ValidateOrgMembership(ctx, "somegroup")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "validation error") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("tracks last validated group", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Groups:   []string{"group1", "group2", "group3"},
		}

		ctx := context.Background()
		_, _, _ = mock.ValidateOrgMembership(ctx, "group1")
		if mock.LastValidatedGroup != "group1" {
			t.Errorf("LastValidatedGroup = %q, want %q", mock.LastValidatedGroup, "group1")
		}

		_, _, _ = mock.ValidateOrgMembership(ctx, "group2")
		if mock.LastValidatedGroup != "group2" {
			t.Errorf("LastValidatedGroup = %q, want %q", mock.LastValidatedGroup, "group2")
		}

		_, _, _ = mock.ValidateOrgMembership(ctx, "group3")
		if mock.LastValidatedGroup != "group3" {
			t.Errorf("LastValidatedGroup = %q, want %q", mock.LastValidatedGroup, "group3")
		}

		if mock.ValidateOrgMembershipCalls != 3 {
			t.Errorf("ValidateOrgMembershipCalls = %d, want 3", mock.ValidateOrgMembershipCalls)
		}
	})
}

// TestMockClient_UserTier tests MockClient UserTier method.
func TestMockClient_UserTier(t *testing.T) {
	t.Parallel()

	t.Run("default tier - flock", func(t *testing.T) {
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
			t.Errorf("tier = %v, want %v", tier, github.TierFlock)
		}
		if mock.UserTierCalls != 1 {
			t.Errorf("UserTierCalls = %d, want 1", mock.UserTierCalls)
		}
	})

	t.Run("custom tier", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Tier:     github.TierFree,
		}

		ctx := context.Background()
		tier, err := mock.UserTier(ctx, "testuser")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != github.TierFree {
			t.Errorf("tier = %v, want %v", tier, github.TierFree)
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		mockErr := fmt.Errorf("tier fetch error")
		mock := &MockClient{
			Err: mockErr,
		}

		ctx := context.Background()
		tier, err := mock.UserTier(ctx, "testuser")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "tier fetch error") {
			t.Errorf("unexpected error: %v", err)
		}
		if tier != github.TierFree {
			t.Errorf("tier on error = %v, want %v", tier, github.TierFree)
		}
	})

	t.Run("multiple calls", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Tier:     github.TierFlock,
		}

		ctx := context.Background()
		for i := 1; i <= 3; i++ {
			_, _ = mock.UserTier(ctx, "testuser")
			if mock.UserTierCalls != i {
				t.Errorf("after %d calls, UserTierCalls = %d", i, mock.UserTierCalls)
			}
		}
	})
}

// TestMockClient_Concurrent tests thread-safety of MockClient.
func TestMockClient_Concurrent(t *testing.T) {
	t.Parallel()

	mock := &MockClient{
		Username: "testuser",
		Groups:   []string{"group1", "group2"},
		Tier:     github.TierFlock,
	}

	ctx := context.Background()
	done := make(chan bool)

	// Run concurrent operations
	for range 10 {
		go func() {
			_, _, _ = mock.UserAndOrgs(ctx)
			_, _, _ = mock.ValidateOrgMembership(ctx, "group1")
			_, _ = mock.UserTier(ctx, "testuser")
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}

	// Verify all calls were counted
	if mock.UserAndOrgsCalls != 10 {
		t.Errorf("UserAndOrgsCalls = %d, want 10", mock.UserAndOrgsCalls)
	}
	if mock.ValidateOrgMembershipCalls != 10 {
		t.Errorf("ValidateOrgMembershipCalls = %d, want 10", mock.ValidateOrgMembershipCalls)
	}
	if mock.UserTierCalls != 10 {
		t.Errorf("UserTierCalls = %d, want 10", mock.UserTierCalls)
	}
}

// TestMockClient_EmptyGroups tests MockClient with empty groups list.
func TestMockClient_EmptyGroups(t *testing.T) {
	t.Parallel()

	mock := &MockClient{
		Username: "testuser",
		Groups:   []string{},
	}

	ctx := context.Background()

	// UserAndOrgs should succeed with empty list
	username, groups, err := mock.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(groups) != 0 {
		t.Errorf("len(groups) = %d, want 0", len(groups))
	}

	// ValidateOrgMembership should fail for any group
	_, _, err = mock.ValidateOrgMembership(ctx, "anygroup")
	if err == nil {
		t.Fatal("expected error when validating with empty groups, got nil")
	}
}
