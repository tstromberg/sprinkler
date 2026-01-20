// Package platform provides platform type definitions and detection logic
// for multi-platform webhook support (GitHub, GitLab, Gitea, Gitee).
package platform

import (
	"errors"
	"net/http"
	"strings"
)

// Type represents a Git platform (GitHub, GitLab, Gitea, or Gitee).
type Type string

const (
	// GitHub represents GitHub.com or GitHub Enterprise.
	GitHub Type = "github"
	// GitLab represents GitLab.com or self-hosted GitLab.
	GitLab Type = "gitlab"
	// Gitea represents Codeberg.org or other Gitea instances.
	Gitea Type = "gitea"
	// Gitee represents Gitee.com or other Gitee instances.
	Gitee Type = "gitee"
)

// DefaultBaseURLs maps platform types to their default public instance URLs.
var DefaultBaseURLs = map[Type]string{
	GitHub: "https://github.com",
	GitLab: "https://gitlab.com",
	Gitea:  "https://codeberg.org",
	Gitee:  "https://gitee.com",
}

// FromString converts a string to a Type, returning GitHub as default.
func FromString(s string) Type {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "gitlab":
		return GitLab
	case "gitea":
		return Gitea
	case "gitee":
		return Gitee
	default:
		return GitHub
	}
}

// Validate checks if the platform type is valid.
func (t Type) Validate() error {
	switch t {
	case GitHub, GitLab, Gitea, Gitee:
		return nil
	default:
		return errors.New("invalid platform type")
	}
}

// String returns the string representation of the platform type.
func (t Type) String() string {
	return string(t)
}

// DetectFromWebhookHeaders detects the platform from webhook signature headers.
// This is used for automatic platform detection from incoming webhooks.
func DetectFromWebhookHeaders(headers http.Header) Type {
	// GitHub uses X-Hub-Signature-256
	if headers.Get("X-Hub-Signature-256") != "" || headers.Get("X-Hub-Signature") != "" {
		return GitHub
	}

	// GitLab uses X-Gitlab-Token
	if headers.Get("X-Gitlab-Token") != "" || headers.Get("X-Gitlab-Event") != "" {
		return GitLab
	}

	// Gitea uses X-Gitea-Signature
	if headers.Get("X-Gitea-Signature") != "" || headers.Get("X-Gitea-Event") != "" {
		return Gitea
	}

	// Gitee uses X-Gitee-Token
	if headers.Get("X-Gitee-Token") != "" || headers.Get("X-Gitee-Event") != "" {
		return Gitee
	}

	// Default to GitHub for backward compatibility
	return GitHub
}

// DefaultAllowedBaseURLs defines the hardcoded list of allowed public instances.
// These are trusted instances that don't require additional SSRF validation.
var DefaultAllowedBaseURLs = map[Type][]string{
	GitHub: {
		"https://github.com",
		"https://api.github.com",
	},
	GitLab: {
		"https://gitlab.com",
	},
	Gitea: {
		"https://codeberg.org",
	},
	Gitee: {
		"https://gitee.com",
	},
}

// IsAllowedBaseURL checks if a base URL is in the allowed list (either default or custom).
// If customAllowed is nil, allows any URL (whitelist disabled).
// If customAllowed is empty slice, only allows default URLs.
// If customAllowed has values, allows default URLs + custom URLs.
func IsAllowedBaseURL(platformType Type, baseURL string, customAllowed []string) bool {
	if baseURL == "" {
		return true // Empty means use default
	}

	// nil slice = whitelist disabled, allow all
	if customAllowed == nil {
		return true
	}

	// Normalize URL for comparison
	normalized := strings.TrimSuffix(strings.ToLower(baseURL), "/")

	// Check default allowed list first
	if defaults, ok := DefaultAllowedBaseURLs[platformType]; ok {
		for _, allowed := range defaults {
			if strings.EqualFold(normalized, allowed) {
				return true
			}
		}
	}

	// Check custom allowed list
	for _, allowed := range customAllowed {
		if strings.EqualFold(normalized, strings.TrimSuffix(allowed, "/")) {
			return true
		}
	}

	return false
}
