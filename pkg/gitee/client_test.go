package gitee

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

	t.Run("with all parameters", func(t *testing.T) {
		t.Parallel()
		token := "test-token-123"
		baseURL := "https://gitee.com"
		logger := slog.Default()

		client := NewClient(token, baseURL, logger)

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

	t.Run("with nil logger", func(t *testing.T) {
		t.Parallel()
		client := NewClient("token", "https://gitee.com", nil)

		if client.logger == nil {
			t.Error("logger should not be nil, expected default discard logger")
		}
	})

	t.Run("with empty baseURL", func(t *testing.T) {
		t.Parallel()
		client := NewClient("token", "", nil)

		if client.baseURL != "https://gitee.com" {
			t.Errorf("baseURL = %q, want %q", client.baseURL, "https://gitee.com")
		}
	})

	t.Run("with trailing slash in baseURL", func(t *testing.T) {
		t.Parallel()
		client := NewClient("token", "https://gitee.com/", nil)

		if client.baseURL != "https://gitee.com" {
			t.Errorf("baseURL = %q, want %q (trailing slash should be removed)", client.baseURL, "https://gitee.com")
		}
	})

	t.Run("with custom baseURL", func(t *testing.T) {
		t.Parallel()
		customURL := "https://gitee.example.com"
		client := NewClient("token", customURL, nil)

		if client.baseURL != customURL {
			t.Errorf("baseURL = %q, want %q", client.baseURL, customURL)
		}
	})
}

// TestAuthenticatedUser_Success tests successful user authentication.
func TestAuthenticatedUser_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v5/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "token test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") != "webhook-sprinkler/1.0" {
			t.Errorf("unexpected user-agent header: %s", r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 12345})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("AuthenticatedUser failed: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("username = %q, want %q", user.Login, "testuser")
	}
	if user.ID != 12345 {
		t.Errorf("user ID = %d, want %d", user.ID, 12345)
	}
}

// TestAuthenticatedUser_Unauthorized tests 401 response.
func TestAuthenticatedUser_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "invalid Gitee token") {
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
		_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("username = %q, want %q", user.Login, "testuser")
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
		_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("username = %q, want %q", user.Login, "testuser")
	}
	if attempts >= 2 {
		t.Logf("successfully retried %d times", attempts)
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
		t.Errorf("expected at least 3 attempts due to retry, got %d", attempts)
	}
}

// TestAuthenticatedUser_EmptyUsername tests response with empty username.
func TestAuthenticatedUser_EmptyUsername(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "", ID: 123})
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

// TestAuthenticatedUser_MalformedJSON tests handling of malformed JSON.
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

// TestAuthenticatedUser_UnexpectedStatus tests handling of unexpected status codes.
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

// TestAuthenticatedUser_NetworkError tests handling of network errors.
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
		_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("username = %q, want %q", user.Login, "testuser")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestUserOrganizations_Success tests successful org listing.
func TestUserOrganizations_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v5/user/orgs" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "token test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}

		w.WriteHeader(http.StatusOK)
		orgs := []Organization{
			{Login: "org1", ID: 1},
			{Login: "org2", ID: 2},
			{Login: "org3", ID: 3},
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
	if orgs[0].Login != "org1" {
		t.Errorf("orgs[0].Login = %q, want %q", orgs[0].Login, "org1")
	}
}

// TestUserOrganizations_EmptyList tests response with empty organization list.
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
	if !strings.Contains(err.Error(), "invalid Gitee token") {
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

// TestUserOrganizations_ServerError tests 500 response with retry.
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
		orgs := []Organization{{Login: "org1", ID: 1}}
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

// TestUserOrganizations_BadGateway tests 502 response with retry.
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
		orgs := []Organization{{Login: "org1", ID: 1}}
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
		t.Logf("successfully retried %d times", attempts)
	}
}

// TestUserOrganizations_ServiceUnavailable tests 503 response with retry.
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
		t.Errorf("expected at least 3 attempts due to retry, got %d", attempts)
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

// TestUserOrganizations_UnexpectedStatus tests handling of unexpected status codes.
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

// TestUserOrganizations_NetworkError tests handling of network errors.
func TestUserOrganizations_NetworkError(t *testing.T) {
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
		_ = json.NewEncoder(w).Encode([]Organization{{Login: "org1", ID: 1}})
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

// TestUserAndOrgs_Success tests successful user and org retrieval.
func TestUserAndOrgs_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "org1", ID: 1},
				{Login: "org2", ID: 2},
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

// TestUserAndOrgs_AuthenticationFails tests failure in AuthenticatedUser.
func TestUserAndOrgs_AuthenticationFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v5/user" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err == nil {
		t.Fatal("expected error when authentication fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get authenticated user") {
		t.Errorf("unexpected error: %v", err)
	}
	if username != "" {
		t.Errorf("username = %q, want empty string", username)
	}
	if orgs != nil {
		t.Errorf("orgs = %v, want nil", orgs)
	}
}

// TestUserAndOrgs_OrganizationsFails tests failure in userOrganizations.
func TestUserAndOrgs_OrganizationsFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err == nil {
		t.Fatal("expected error when organizations fetch fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get user organizations") {
		t.Errorf("unexpected error: %v", err)
	}
	if username != "" {
		t.Errorf("username = %q, want empty string", username)
	}
	if orgs != nil {
		t.Errorf("orgs = %v, want nil", orgs)
	}
}

// TestUserAndOrgs_EmptyOrganizations tests user with no organizations.
func TestUserAndOrgs_EmptyOrganizations(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]Organization{})
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
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "org1", ID: 1},
				{Login: "targetorg", ID: 2},
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
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "org1", ID: 1},
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

	client := NewClient("test-token", "https://gitee.com", nil)

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

	client := NewClient("test-token", "https://gitee.com", nil)

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
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "TestOrg", ID: 1},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// Request with lowercase should match TestOrg
	_, _, err := client.ValidateOrgMembership(ctx, "testorg")
	if err != nil {
		t.Errorf("case-insensitive matching failed: %v", err)
	}
}

// TestValidateOrgMembership_CaseInsensitiveUppercase tests case-insensitive matching with uppercase request.
func TestValidateOrgMembership_CaseInsensitiveUppercase(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "testorg", ID: 1},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// Request with uppercase should match testorg
	_, _, err := client.ValidateOrgMembership(ctx, "TESTORG")
	if err != nil {
		t.Errorf("case-insensitive matching failed: %v", err)
	}
}

// TestValidateOrgMembership_UserAndOrgsFails tests validation when UserAndOrgs fails.
func TestValidateOrgMembership_UserAndOrgsFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v5/user" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	client := NewClient("invalid-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "someorg")
	if err == nil {
		t.Fatal("expected error when UserAndOrgs fails, got nil")
	}
}

// TestUserTier_Success tests successful tier retrieval.
func TestUserTier_Success(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://gitee.com", nil)

	ctx := context.Background()
	tier, err := client.UserTier(ctx, "testuser")
	if err != nil {
		t.Fatalf("UserTier failed: %v", err)
	}
	if tier != github.TierFlock {
		t.Errorf("tier = %q, want %q", tier, github.TierFlock)
	}
}

// TestUserTier_EmptyUsername tests tier retrieval with empty username.
func TestUserTier_EmptyUsername(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://gitee.com", nil)

	ctx := context.Background()
	tier, err := client.UserTier(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty username, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
	// Should still return TierFlock even on error
	if tier != github.TierFlock {
		t.Errorf("tier = %q, want %q", tier, github.TierFlock)
	}
}

// TestUserTier_AlwaysReturnsFlock tests that tier is always Flock.
func TestUserTier_AlwaysReturnsFlock(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://gitee.com", nil)

	ctx := context.Background()
	testUsers := []string{"user1", "user2", "user3", "org1", "enterprise-user"}

	for _, username := range testUsers {
		tier, err := client.UserTier(ctx, username)
		if err != nil {
			t.Fatalf("UserTier failed for %q: %v", username, err)
		}
		if tier != github.TierFlock {
			t.Errorf("tier for %q = %q, want %q", username, tier, github.TierFlock)
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
		_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
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
		_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for context timeout, got nil")
	}
}

// TestLargeResponseBody tests that large responses are limited.
func TestLargeResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write a very large response (> 1MB limit)
		large := strings.Repeat("x", 2*1024*1024)
		_, _ = w.Write([]byte(`{"login":"` + large + `", "id": 123}`))
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
		{"InternalServerError", http.StatusInternalServerError, true},
		{"BadGateway", http.StatusBadGateway, true},
		{"ServiceUnavailable", http.StatusServiceUnavailable, true},
		{"GatewayTimeout", http.StatusGatewayTimeout, false},
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

// TestMultipleRetryScenarios tests various retry scenarios.
func TestMultipleRetryScenarios(t *testing.T) {
	t.Parallel()

	t.Run("all attempts fail with 500", func(t *testing.T) {
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
			t.Fatal("expected error when all retries fail, got nil")
		}
		if attempts < 3 {
			t.Errorf("expected at least 3 attempts, got %d", attempts)
		}
	})

	t.Run("success on last attempt", func(t *testing.T) {
		t.Parallel()
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		}))
		defer server.Close()

		client := NewClient("test-token", server.URL, nil)
		ctx := context.Background()

		user, err := client.AuthenticatedUser(ctx)
		if err != nil {
			t.Fatalf("expected success on last attempt, got error: %v", err)
		}
		if user.Login != "testuser" {
			t.Errorf("username = %q, want %q", user.Login, "testuser")
		}
		if attempts != 3 {
			t.Errorf("expected exactly 3 attempts, got %d", attempts)
		}
	})
}

// TestReadBodyError tests handling when reading response body fails.
func TestReadBodyError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// Write less than promised to potentially trigger read error
		_, _ = w.Write([]byte(`{"login":"test", "id": 123}`))
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)
	// Use a custom client with very small timeout
	client.httpClient.Timeout = 1 * time.Nanosecond

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error due to timeout, got nil")
	}
}

// TestUserAndOrgs_WithLogging tests UserAndOrgs with a logger to ensure logging works.
func TestUserAndOrgs_WithLogging(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{{Login: "org1", ID: 1}}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	logger := slog.Default()
	client := NewClient("test-token", server.URL, logger)

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("UserAndOrgs failed: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// TestValidateOrgMembership_WithLogging tests ValidateOrgMembership with logger.
func TestValidateOrgMembership_WithLogging(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{{Login: "testorg", ID: 1}}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	logger := slog.Default()
	client := NewClient("test-token", server.URL, logger)

	ctx := context.Background()
	username, orgs, err := client.ValidateOrgMembership(ctx, "testorg")
	if err != nil {
		t.Fatalf("ValidateOrgMembership failed: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// TestMultipleOrganizations tests handling of users with multiple organizations.
func TestMultipleOrganizations(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "org1", ID: 1},
				{Login: "org2", ID: 2},
				{Login: "org3", ID: 3},
				{Login: "org4", ID: 4},
				{Login: "org5", ID: 5},
			}
			_ = json.NewEncoder(w).Encode(orgs)
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
	if len(orgs) != 5 {
		t.Errorf("len(orgs) = %d, want 5", len(orgs))
	}
	// Verify all org names are present
	expectedOrgs := map[string]bool{
		"org1": false, "org2": false, "org3": false, "org4": false, "org5": false,
	}
	for _, org := range orgs {
		if _, exists := expectedOrgs[org]; exists {
			expectedOrgs[org] = true
		}
	}
	for org, found := range expectedOrgs {
		if !found {
			t.Errorf("expected org %q not found in results", org)
		}
	}
}

// TestValidateOrgMembership_FirstOrg tests validation with first org in list.
func TestValidateOrgMembership_FirstOrg(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "firstorg", ID: 1},
				{Login: "secondorg", ID: 2},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "firstorg")
	if err != nil {
		t.Errorf("validation of first org failed: %v", err)
	}
}

// TestValidateOrgMembership_LastOrg tests validation with last org in list.
func TestValidateOrgMembership_LastOrg(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "firstorg", ID: 1},
				{Login: "secondorg", ID: 2},
				{Login: "lastorg", ID: 3},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "lastorg")
	if err != nil {
		t.Errorf("validation of last org failed: %v", err)
	}
}

// TestOrgNameWithSpaces tests org name validation with leading/trailing spaces.
func TestOrgNameWithSpaces(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v5/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser", ID: 123})
		case "/api/v5/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{{Login: "testorg", ID: 1}}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)

	ctx := context.Background()
	// Test with leading and trailing spaces - should be trimmed
	_, _, err := client.ValidateOrgMembership(ctx, "  testorg  ")
	if err != nil {
		t.Errorf("validation with trimmed org name failed: %v", err)
	}
}

// TestUserTier_DifferentUsernames tests tier retrieval with various usernames.
func TestUserTier_DifferentUsernames(t *testing.T) {
	t.Parallel()

	testCases := []string{
		"user",
		"user-with-dashes",
		"user_with_underscores",
		"UserWithCaps",
		"user123",
	}

	client := NewClient("test-token", "https://gitee.com", nil)
	ctx := context.Background()

	for _, username := range testCases {
		tier, err := client.UserTier(ctx, username)
		if err != nil {
			t.Errorf("UserTier failed for %q: %v", username, err)
		}
		if tier != github.TierFlock {
			t.Errorf("tier for %q = %q, want %q", username, tier, github.TierFlock)
		}
	}
}

// TestClientTimeout tests that the client has correct timeout configured.
func TestClientTimeout(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", "https://gitee.com", nil)

	if client.httpClient.Timeout != clientTimeout {
		t.Errorf("client timeout = %v, want %v", client.httpClient.Timeout, clientTimeout)
	}
	if client.httpClient.Timeout != 10*time.Second {
		t.Errorf("client timeout = %v, want 10s", client.httpClient.Timeout)
	}
}

// TestBaseURLHandling tests various baseURL scenarios.
func TestBaseURLHandling(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", "https://gitee.com"},
		{"default", "https://gitee.com", "https://gitee.com"},
		{"with trailing slash", "https://gitee.com/", "https://gitee.com"},
		{"custom domain", "https://gitee.example.com", "https://gitee.example.com"},
		{"custom with trailing slash", "https://gitee.example.com/", "https://gitee.example.com"},
		{"multiple trailing slashes", "https://gitee.com///", "https://gitee.com//"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := NewClient("token", tc.input, nil)
			if client.baseURL != tc.expected {
				t.Errorf("baseURL = %q, want %q", client.baseURL, tc.expected)
			}
		})
	}
}

// TestConcurrentRequests tests that the client handles concurrent requests safely.
func TestConcurrentRequests(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/api/v5/user" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: fmt.Sprintf("user%d", requestCount), ID: requestCount})
		}
	}))
	defer server.Close()

	client := NewClient("test-token", server.URL, nil)
	ctx := context.Background()

	// Make multiple concurrent requests
	done := make(chan bool, 5)
	for id := range 5 {
		go func(id int) {
			_, err := client.AuthenticatedUser(ctx)
			if err != nil {
				t.Errorf("concurrent request %d failed: %v", id, err)
			}
			done <- true
		}(id)
	}

	// Wait for all requests to complete
	for range 5 {
		<-done
	}
}

// TestMockClient_UserAndOrgs tests the MockClient's UserAndOrgs method.
func TestMockClient_UserAndOrgs(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"org1", "org2", "org3"},
		}

		ctx := context.Background()
		username, orgs, err := mock.UserAndOrgs(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "mockuser" {
			t.Errorf("username = %q, want %q", username, "mockuser")
		}
		if len(orgs) != 3 {
			t.Errorf("len(orgs) = %d, want 3", len(orgs))
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
		username, orgs, err := mock.UserAndOrgs(ctx)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "mock error") {
			t.Errorf("unexpected error: %v", err)
		}
		if username != "" {
			t.Errorf("username = %q, want empty", username)
		}
		if orgs != nil {
			t.Errorf("orgs = %v, want nil", orgs)
		}
		if mock.UserAndOrgsCalls != 1 {
			t.Errorf("UserAndOrgsCalls = %d, want 1", mock.UserAndOrgsCalls)
		}
	})

	t.Run("empty organizations", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{},
		}

		ctx := context.Background()
		username, orgs, err := mock.UserAndOrgs(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "mockuser" {
			t.Errorf("username = %q, want %q", username, "mockuser")
		}
		if len(orgs) != 0 {
			t.Errorf("len(orgs) = %d, want 0", len(orgs))
		}
	})

	t.Run("multiple calls tracking", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"org1"},
		}

		ctx := context.Background()
		for range 5 {
			_, _, _ = mock.UserAndOrgs(ctx)
		}

		if mock.UserAndOrgsCalls != 5 {
			t.Errorf("UserAndOrgsCalls = %d, want 5", mock.UserAndOrgsCalls)
		}
	})
}

// TestMockClient_ValidateOrgMembership tests the MockClient's ValidateOrgMembership method.
func TestMockClient_ValidateOrgMembership(t *testing.T) {
	t.Parallel()

	t.Run("success - is member", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"org1", "org2", "org3"},
		}

		ctx := context.Background()
		username, orgs, err := mock.ValidateOrgMembership(ctx, "org2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "mockuser" {
			t.Errorf("username = %q, want %q", username, "mockuser")
		}
		if len(orgs) != 3 {
			t.Errorf("len(orgs) = %d, want 3", len(orgs))
		}
		if mock.LastValidatedOrg != "org2" {
			t.Errorf("LastValidatedOrg = %q, want %q", mock.LastValidatedOrg, "org2")
		}
		if mock.ValidateOrgMembershipCalls != 1 {
			t.Errorf("ValidateOrgMembershipCalls = %d, want 1", mock.ValidateOrgMembershipCalls)
		}
	})

	t.Run("not a member", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"org1", "org2"},
		}

		ctx := context.Background()
		username, orgs, err := mock.ValidateOrgMembership(ctx, "org3")
		if err == nil {
			t.Fatal("expected error for non-member, got nil")
		}
		if !strings.Contains(err.Error(), "not a member") {
			t.Errorf("unexpected error: %v", err)
		}
		// Should still return username and orgs
		if username != "mockuser" {
			t.Errorf("username = %q, want %q", username, "mockuser")
		}
		if len(orgs) != 2 {
			t.Errorf("len(orgs) = %d, want 2", len(orgs))
		}
		if mock.LastValidatedOrg != "org3" {
			t.Errorf("LastValidatedOrg = %q, want %q", mock.LastValidatedOrg, "org3")
		}
	})

	t.Run("error before membership check", func(t *testing.T) {
		t.Parallel()
		mockErr := fmt.Errorf("auth error")
		mock := &MockClient{
			Err:      mockErr,
			Username: "mockuser",
			Orgs:     []string{"org1"},
		}

		ctx := context.Background()
		username, orgs, err := mock.ValidateOrgMembership(ctx, "org1")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth error") {
			t.Errorf("unexpected error: %v", err)
		}
		if username != "" {
			t.Errorf("username = %q, want empty", username)
		}
		if orgs != nil {
			t.Errorf("orgs = %v, want nil", orgs)
		}
		if mock.LastValidatedOrg != "org1" {
			t.Errorf("LastValidatedOrg = %q, want %q", mock.LastValidatedOrg, "org1")
		}
	})

	t.Run("first org in list", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"firstorg", "secondorg", "thirdorg"},
		}

		ctx := context.Background()
		_, _, err := mock.ValidateOrgMembership(ctx, "firstorg")
		if err != nil {
			t.Errorf("validation failed for first org: %v", err)
		}
	})

	t.Run("last org in list", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"firstorg", "secondorg", "thirdorg"},
		}

		ctx := context.Background()
		_, _, err := mock.ValidateOrgMembership(ctx, "thirdorg")
		if err != nil {
			t.Errorf("validation failed for last org: %v", err)
		}
	})

	t.Run("multiple calls tracking", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"org1"},
		}

		ctx := context.Background()
		for range 3 {
			_, _, _ = mock.ValidateOrgMembership(ctx, "org1")
		}

		if mock.ValidateOrgMembershipCalls != 3 {
			t.Errorf("ValidateOrgMembershipCalls = %d, want 3", mock.ValidateOrgMembershipCalls)
		}
	})

	t.Run("tracks last validated org", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Orgs:     []string{"org1", "org2", "org3"},
		}

		ctx := context.Background()
		_, _, _ = mock.ValidateOrgMembership(ctx, "org1")
		_, _, _ = mock.ValidateOrgMembership(ctx, "org2")
		_, _, _ = mock.ValidateOrgMembership(ctx, "org3")

		if mock.LastValidatedOrg != "org3" {
			t.Errorf("LastValidatedOrg = %q, want %q", mock.LastValidatedOrg, "org3")
		}
	})
}

// TestMockClient_UserTier tests the MockClient's UserTier method.
func TestMockClient_UserTier(t *testing.T) {
	t.Parallel()

	t.Run("default tier - Flock", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
		}

		ctx := context.Background()
		tier, err := mock.UserTier(ctx, "mockuser")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != github.TierFlock {
			t.Errorf("tier = %q, want %q", tier, github.TierFlock)
		}
		if mock.UserTierCalls != 1 {
			t.Errorf("UserTierCalls = %d, want 1", mock.UserTierCalls)
		}
	})

	t.Run("custom tier - Pro", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Tier:     github.TierPro,
		}

		ctx := context.Background()
		tier, err := mock.UserTier(ctx, "mockuser")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != github.TierPro {
			t.Errorf("tier = %q, want %q", tier, github.TierPro)
		}
	})

	t.Run("custom tier - Free", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
			Tier:     github.TierFree,
		}

		ctx := context.Background()
		tier, err := mock.UserTier(ctx, "mockuser")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != github.TierFree {
			t.Errorf("tier = %q, want %q", tier, github.TierFree)
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		mockErr := fmt.Errorf("tier error")
		mock := &MockClient{
			Err: mockErr,
		}

		ctx := context.Background()
		tier, err := mock.UserTier(ctx, "mockuser")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "tier error") {
			t.Errorf("unexpected error: %v", err)
		}
		// Should still return TierFlock on error
		if tier != github.TierFlock {
			t.Errorf("tier = %q, want %q", tier, github.TierFlock)
		}
		if mock.UserTierCalls != 1 {
			t.Errorf("UserTierCalls = %d, want 1", mock.UserTierCalls)
		}
	})

	t.Run("multiple calls tracking", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
		}

		ctx := context.Background()
		for range 4 {
			_, _ = mock.UserTier(ctx, "mockuser")
		}

		if mock.UserTierCalls != 4 {
			t.Errorf("UserTierCalls = %d, want 4", mock.UserTierCalls)
		}
	})

	t.Run("empty username still works", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "mockuser",
		}

		ctx := context.Background()
		tier, err := mock.UserTier(ctx, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tier != github.TierFlock {
			t.Errorf("tier = %q, want %q", tier, github.TierFlock)
		}
	})
}

// TestMockClient_ConcurrentAccess tests thread-safety of MockClient.
func TestMockClient_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	mock := &MockClient{
		Username: "mockuser",
		Orgs:     []string{"org1", "org2", "org3"},
	}

	ctx := context.Background()
	done := make(chan bool, 30)

	// Run 30 concurrent operations
	for range 10 {
		go func() {
			_, _, _ = mock.UserAndOrgs(ctx)
			done <- true
		}()
	}

	for range 10 {
		go func() {
			_, _, _ = mock.ValidateOrgMembership(ctx, "org1")
			done <- true
		}()
	}

	for range 10 {
		go func() {
			_, _ = mock.UserTier(ctx, "mockuser")
			done <- true
		}()
	}

	// Wait for all operations to complete
	for range 30 {
		<-done
	}

	// Verify all calls were tracked
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

// TestMockClient_ImplementsInterface verifies MockClient implements github.APIClient.
func TestMockClient_ImplementsInterface(t *testing.T) {
	t.Parallel()

	var _ github.APIClient = (*MockClient)(nil)

	// Also test that it works as an interface
	var client github.APIClient = &MockClient{
		Username: "mockuser",
		Orgs:     []string{"org1"},
	}

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "mockuser" {
		t.Errorf("username = %q, want %q", username, "mockuser")
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
}

// TestMockClient_EmptyOrgs tests MockClient with empty organization list.
func TestMockClient_EmptyOrgs(t *testing.T) {
	t.Parallel()

	mock := &MockClient{
		Username: "mockuser",
		Orgs:     []string{},
	}

	ctx := context.Background()

	// Any org validation should fail
	_, _, err := mock.ValidateOrgMembership(ctx, "anyorg")
	if err == nil {
		t.Fatal("expected error for validation with empty org list, got nil")
	}
	if !strings.Contains(err.Error(), "not a member") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMockClient_NilOrgs tests MockClient with nil organization list.
func TestMockClient_NilOrgs(t *testing.T) {
	t.Parallel()

	mock := &MockClient{
		Username: "mockuser",
		Orgs:     nil,
	}

	ctx := context.Background()

	username, orgs, err := mock.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if username != "mockuser" {
		t.Errorf("username = %q, want %q", username, "mockuser")
	}
	if orgs != nil {
		t.Errorf("orgs = %v, want nil", orgs)
	}

	// Any org validation should fail
	_, _, err = mock.ValidateOrgMembership(ctx, "anyorg")
	if err == nil {
		t.Fatal("expected error for validation with nil org list, got nil")
	}
}

// TestMockClient_StateReset tests that mock state can be reset between tests.
func TestMockClient_StateReset(t *testing.T) {
	t.Parallel()

	mock := &MockClient{
		Username: "mockuser",
		Orgs:     []string{"org1"},
	}

	ctx := context.Background()

	// Make some calls
	_, _, err := mock.UserAndOrgs(ctx)
	_ = err
	_, _, err = mock.ValidateOrgMembership(ctx, "org1")
	_ = err
	_, err = mock.UserTier(ctx, "mockuser")
	_ = err

	if mock.UserAndOrgsCalls != 1 {
		t.Errorf("UserAndOrgsCalls = %d, want 1", mock.UserAndOrgsCalls)
	}
	if mock.ValidateOrgMembershipCalls != 1 {
		t.Errorf("ValidateOrgMembershipCalls = %d, want 1", mock.ValidateOrgMembershipCalls)
	}
	if mock.UserTierCalls != 1 {
		t.Errorf("UserTierCalls = %d, want 1", mock.UserTierCalls)
	}

	// Create new mock (simulating test reset)
	mock = &MockClient{
		Username: "mockuser",
		Orgs:     []string{"org1"},
	}

	if mock.UserAndOrgsCalls != 0 {
		t.Errorf("UserAndOrgsCalls after reset = %d, want 0", mock.UserAndOrgsCalls)
	}
	if mock.ValidateOrgMembershipCalls != 0 {
		t.Errorf("ValidateOrgMembershipCalls after reset = %d, want 0", mock.ValidateOrgMembershipCalls)
	}
	if mock.UserTierCalls != 0 {
		t.Errorf("UserTierCalls after reset = %d, want 0", mock.UserTierCalls)
	}
}
