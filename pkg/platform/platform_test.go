package platform

import (
	"net/http"
	"testing"
)

func TestFromString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Type
	}{
		{"GitHub", "github", GitHub},
		{"GitHub uppercase", "GITHUB", GitHub},
		{"GitHub with spaces", " github ", GitHub},
		{"GitLab", "gitlab", GitLab},
		{"GitLab uppercase", "GITLAB", GitLab},
		{"Gitea", "gitea", Gitea},
		{"Gitea uppercase", "GITEA", Gitea},
		{"Gitee", "gitee", Gitee},
		{"Gitee uppercase", "GITEE", Gitee},
		{"Empty defaults to GitHub", "", GitHub},
		{"Unknown defaults to GitHub", "unknown", GitHub},
		{"Invalid defaults to GitHub", "bitbucket", GitHub},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromString(tt.input)
			if result != tt.expected {
				t.Errorf("FromString(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		platform  Type
		expectErr bool
	}{
		{"GitHub valid", GitHub, false},
		{"GitLab valid", GitLab, false},
		{"Gitea valid", Gitea, false},
		{"Gitee valid", Gitee, false},
		{"Invalid platform", Type("invalid"), true},
		{"Empty platform", Type(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.platform.Validate()
			if (err != nil) != tt.expectErr {
				t.Errorf("Validate() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name     string
		platform Type
		expected string
	}{
		{"GitHub", GitHub, "github"},
		{"GitLab", GitLab, "gitlab"},
		{"Gitea", Gitea, "gitea"},
		{"Gitee", Gitee, "gitee"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.platform.String()
			if result != tt.expected {
				t.Errorf("String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetectFromWebhookHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected Type
	}{
		{
			name: "GitHub X-Hub-Signature-256",
			headers: http.Header{
				"X-Hub-Signature-256": []string{"sha256=abc123"},
			},
			expected: GitHub,
		},
		{
			name: "GitHub X-Hub-Signature (legacy)",
			headers: http.Header{
				"X-Hub-Signature": []string{"sha1=abc123"},
			},
			expected: GitHub,
		},
		{
			name: "GitLab X-Gitlab-Token",
			headers: http.Header{
				"X-Gitlab-Token": []string{"secret123"},
			},
			expected: GitLab,
		},
		{
			name: "GitLab X-Gitlab-Event",
			headers: http.Header{
				"X-Gitlab-Event": []string{"Merge Request Hook"},
			},
			expected: GitLab,
		},
		{
			name: "Gitea X-Gitea-Signature",
			headers: http.Header{
				"X-Gitea-Signature": []string{"abc123"},
			},
			expected: Gitea,
		},
		{
			name: "Gitea X-Gitea-Event",
			headers: http.Header{
				"X-Gitea-Event": []string{"pull_request"},
			},
			expected: Gitea,
		},
		{
			name: "Gitee X-Gitee-Token",
			headers: http.Header{
				"X-Gitee-Token": []string{"secret123"},
			},
			expected: Gitee,
		},
		{
			name: "Gitee X-Gitee-Event",
			headers: http.Header{
				"X-Gitee-Event": []string{"pull_request"},
			},
			expected: Gitee,
		},
		{
			name:     "No headers defaults to GitHub",
			headers:  http.Header{},
			expected: GitHub,
		},
		{
			name: "Unknown headers default to GitHub",
			headers: http.Header{
				"X-Unknown-Header": []string{"value"},
			},
			expected: GitHub,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectFromWebhookHeaders(tt.headers)
			if result != tt.expected {
				t.Errorf("DetectFromWebhookHeaders() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDefaultBaseURLs(t *testing.T) {
	tests := []struct {
		name     string
		platform Type
		expected string
	}{
		{"GitHub", GitHub, "https://github.com"},
		{"GitLab", GitLab, "https://gitlab.com"},
		{"Gitea", Gitea, "https://codeberg.org"},
		{"Gitee", Gitee, "https://gitee.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, exists := DefaultBaseURLs[tt.platform]
			if !exists {
				t.Errorf("DefaultBaseURLs missing entry for %v", tt.platform)
			}
			if url != tt.expected {
				t.Errorf("DefaultBaseURLs[%v] = %v, want %v", tt.platform, url, tt.expected)
			}
		})
	}
}
