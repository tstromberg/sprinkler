package srv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
	"github.com/codeGROOVE-dev/sprinkler/pkg/platform"
	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
)

const (
	maxOrgNameLength      = 39  // GitHub org name max length
	maxEventTypeCount     = 50  // Reasonable limit for number of event types
	maxEventTypeLength    = 50  // Max length of individual event type
	maxPRsPerSubscription = 200 // Maximum number of PRs to subscribe to
	maxPRURLLength        = 500 // Maximum length of a PR URL
	minPRURLParts         = 4   // Minimum parts in PR URL (owner/repo/pull/number)
	tokenPrefixLength     = 4   // Length of token prefix for logging
)

var (
	// ErrInvalidUsername indicates an invalid GitHub username.
	ErrInvalidUsername = errors.New("invalid username")
	// ErrInvalidURL indicates an invalid URL.
	ErrInvalidURL = errors.New("invalid URL")
)

// Subscription represents a client's subscription criteria.
type Subscription struct {
	Platform       string   `json:"platform,omitempty"` // "github", "gitlab", or "gitea" (defaults to "github")
	BaseURL        string   `json:"base_url,omitempty"` // Instance URL (optional, defaults by platform)
	Organization   string   `json:"organization"`
	Username       string   `json:"-"`
	EventTypes     []string `json:"event_types,omitempty"`
	PullRequests   []string `json:"pull_requests,omitempty"`
	UserEventsOnly bool     `json:"user_events_only,omitempty"`
}

// Validate performs security validation on subscription data.
// customAllowedBaseURLs is the list of additional allowed base URLs configured by the admin.
func (s *Subscription) Validate(ctx context.Context, customAllowedBaseURLs []string) error {
	// Organization is optional when subscribing to specific PRs or my events only
	// The server will validate that the user has access to the resources
	if s.Organization != "" {
		// Allow wildcard to subscribe to all orgs
		if s.Organization == "*" {
			// Wildcard is valid - subscribes to all orgs the user is a member of
			return nil
		}

		if len(s.Organization) > maxOrgNameLength {
			return errors.New("invalid organization name")
		}
		// GitHub org names can only contain alphanumeric characters, hyphens, and underscores
		for _, c := range s.Organization {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return errors.New("invalid organization name format")
			}
		}
	}

	// Validate event types if specified
	if len(s.EventTypes) > maxEventTypeCount {
		return errors.New("too many event types specified")
	}
	for _, et := range s.EventTypes {
		if len(et) > maxEventTypeLength || et == "" {
			return errors.New("invalid event type")
		}
		// GitHub event types typically use underscores and lowercase
		for _, c := range et {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return errors.New("invalid event type format")
			}
		}
	}

	// Validate PR URLs if specified
	if len(s.PullRequests) > 0 {
		if len(s.PullRequests) > maxPRsPerSubscription {
			return errors.New("too many PR URLs specified (max 200)")
		}

		// Validate each PR URL
		for _, u := range s.PullRequests {
			if u == "" {
				return errors.New("empty PR URL")
			}

			// Limit URL length to prevent memory exhaustion
			if len(u) > maxPRURLLength {
				return errors.New("PR URL too long")
			}

			// Basic validation - should be a valid PR/MR URL
			// Supported formats:
			// - GitHub: https://github.com/owner/repo/pull/number
			// - GitLab: https://gitlab.com/owner/repo/-/merge_requests/number
			// - Gitea: https://codeberg.org/owner/repo/pulls/number
			if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
				return errors.New("invalid PR URL format - must be https://")
			}

			// Check if it contains pull request markers
			isPR := strings.Contains(u, "/pull/") ||
				strings.Contains(u, "/pulls/") ||
				strings.Contains(u, "/merge_requests/")
			if !isPR {
				return errors.New("URL must be a pull request or merge request URL")
			}

			// Validate the URL can be parsed to prevent injection
			info, err := parsePRUrl(u)
			if err != nil {
				return errors.New("invalid PR URL structure")
			}
			if info.owner == "" || info.repo == "" || info.prNumber <= 0 {
				return errors.New("invalid PR URL components")
			}
		}
	}

	// Validate base_url if specified
	if s.BaseURL != "" {
		if err := s.validateBaseURL(ctx, customAllowedBaseURLs); err != nil {
			return err
		}
	}

	return nil
}

// validateBaseURL checks base_url for security (SSRF) and whitelist compliance.
func (s *Subscription) validateBaseURL(ctx context.Context, customAllowedBaseURLs []string) error {
	platformType := platform.FromString(s.Platform)

	// Always block internal IPs (even when whitelist is disabled)
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := security.BlockInternalIPs(timeoutCtx, s.BaseURL); err != nil {
		return fmt.Errorf("base_url security check failed: %w", err)
	}

	// Check whitelist (if enabled)
	if !platform.IsAllowedBaseURL(platformType, s.BaseURL, customAllowedBaseURLs) {
		return fmt.Errorf(
			"base_url %q is not in the allowed list for platform %s - "+
				"contact admin to add it via --allowed-base-urls flag",
			s.BaseURL, s.Platform,
		)
	}

	return nil
}

// prURLInfo holds parsed PR URL components.
type prURLInfo struct {
	owner    string
	repo     string
	prNumber int
}

// parsePRUrl extracts owner, repo, and PR number from a PR/MR URL.
// Supports GitHub, GitLab, and Gitea URL formats.
func parsePRUrl(prURL string) (*prURLInfo, error) {
	// Remove protocol
	url := strings.TrimPrefix(prURL, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Split by / and find the host boundary
	parts := strings.Split(url, "/")
	if len(parts) < minPRURLParts+1 { // +1 for host
		return nil, errors.New("invalid PR URL format")
	}

	// Skip the host (first part) to get to owner/repo
	// For github.com/owner/repo/pull/123, parts are: [github.com, owner, repo, pull, 123]
	// For custom.domain.com/owner/repo/pull/123, parts are: [custom.domain.com, owner, repo, pull, 123]
	startIdx := 1 // Skip host
	if len(parts) <= startIdx+1 {
		return nil, errors.New("invalid PR URL format")
	}

	owner := parts[startIdx]
	repo := parts[startIdx+1]

	// Find the PR/MR marker and number (search from after repo)
	var prIndex int
	var numIndex int
	for i := startIdx + 2; i < len(parts); i++ {
		part := parts[i]
		if part == "pull" || part == "pulls" || part == "merge_requests" {
			// GitHub: /pull/123, Gitea: /pulls/123, GitLab: /-/merge_requests/123
			prIndex = i
			numIndex = i + 1
			break
		}
	}

	if prIndex == 0 || numIndex >= len(parts) {
		return nil, errors.New("invalid PR URL format")
	}

	// Validate owner and repo don't contain dangerous characters
	if owner == "" || repo == "" {
		return nil, errors.New("empty owner or repo")
	}

	// Reject path traversal attempts
	if owner == "." || owner == ".." || repo == "." || repo == ".." {
		return nil, errors.New("invalid owner or repo name")
	}

	// Validate names (alphanumeric, dash, underscore, dot)
	for _, c := range owner {
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !valid {
			return nil, errors.New("invalid owner name")
		}
	}
	for _, c := range repo {
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !valid {
			return nil, errors.New("invalid repo name")
		}
	}

	// Parse PR number
	var num int
	if _, err := fmt.Sscanf(parts[numIndex], "%d", &num); err != nil {
		return nil, errors.New("invalid PR number")
	}

	if num <= 0 {
		return nil, errors.New("invalid PR number")
	}

	return &prURLInfo{
		owner:    owner,
		repo:     repo,
		prNumber: num,
	}, nil
}

// Helper functions to reduce cognitive complexity.

func extractEventOrg(payload map[string]any) string {
	// Check repository owner first
	if repo, ok := payload["repository"].(map[string]any); ok {
		if owner, ok := repo["owner"].(map[string]any); ok {
			if login, ok := owner["login"].(string); ok {
				return login
			}
		}
	}
	// Check organization field directly (some events include it)
	if org, ok := payload["organization"].(map[string]any); ok {
		if login, ok := org["login"].(string); ok {
			return login
		}
	}
	return ""
}

func matchesPRSubscription(sub Subscription, payload map[string]any, eventOrg string, userOrgs map[string]bool) bool {
	// For PR subscriptions, check if this event is about one of the subscribed PRs
	// and the user is a member of the organization

	// Only check org membership if we have an eventOrg
	if eventOrg != "" && !userOrgs[strings.ToLower(eventOrg)] {
		// User is not a member of this org, don't deliver the event
		return false
	}

	// Extract PR information from the event
	pr, ok := payload["pull_request"].(map[string]any)
	if !ok {
		return false
	}

	// Get PR number
	prNumber, ok := pr["number"].(float64)
	if !ok {
		return false
	}

	// Get repository info
	repoName := ""
	if repo, ok := payload["repository"].(map[string]any); ok {
		if name, ok := repo["name"].(string); ok {
			repoName = name
		}
	}

	// Check if this PR matches any of the subscribed PRs
	for _, prURL := range sub.PullRequests {
		info, err := parsePRUrl(prURL)
		if err != nil {
			continue
		}

		// Check if this matches the event
		if strings.EqualFold(info.owner, eventOrg) &&
			strings.EqualFold(info.repo, repoName) &&
			int(prNumber) == info.prNumber {
			return true
		}
	}

	// Not one of the subscribed PRs
	return false
}

// matchesForTest is a test helper that creates a minimal client for testing.
// This maintains backward compatibility with existing tests.
func matchesForTest(sub Subscription, event Event, payload map[string]any, userOrgs map[string]bool) bool {
	// Create a minimal client for testing
	ctx := context.Background()
	client := &Client{
		subscription: sub,
		userOrgs:     userOrgs,
		hub: &Hub{
			enforceTiers: false, // Tests default to no enforcement
		},
		tier: github.TierFree,
	}
	return matches(ctx, client, event, payload)
}

func matches(ctx context.Context, client *Client, event Event, payload map[string]any) bool {
	sub := client.subscription
	userOrgs := client.userOrgs

	// Filter private repo events based on tier
	//nolint:errcheck,revive // Type assertions intentionally unchecked; defaults are correct
	if repoData, ok := payload["repository"].(map[string]any); ok {
		private, _ := repoData["private"].(bool)
		repoName, _ := repoData["full_name"].(string)
		if private {
			if !client.CanAccessPrivateRepos() {
				if client.hub.enforceTiers {
					// Enforcement is active - actually filter the event
					logger.Info(ctx, "filtering private repo event (tier enforcement active)", logger.Fields{
						"user":       sub.Username,
						"tier":       string(client.tier),
						"repo":       repoName,
						"event_type": event.Type,
					})
					return false
				}
				// Enforcement not active - log warning but allow event through
				logger.Warn(ctx, "would filter private repo event if enforcement was active", logger.Fields{
					"user":       sub.Username,
					"tier":       string(client.tier),
					"repo":       repoName,
					"event_type": event.Type,
					"suggestion": "upgrade to Pro or Flock tier for private repo access",
				})
			}
		}
	}

	// Check if event type matches subscription
	if len(sub.EventTypes) > 0 {
		found := false
		for _, allowedType := range sub.EventTypes {
			if event.Type == allowedType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Extract the organization from the event
	eventOrg := extractEventOrg(payload)

	// Check if this is a PR subscription (no org required)
	if len(sub.PullRequests) > 0 {
		return matchesPRSubscription(sub, payload, eventOrg, userOrgs)
	}

	// For UserEventsOnly mode (no org required if subscribing to user's events across all orgs)
	if sub.UserEventsOnly {
		// Check org constraints
		if sub.Organization != "" {
			if sub.Organization == "*" {
				// Wildcard - check if user is member of the event's org
				if eventOrg != "" && !userOrgs[strings.ToLower(eventOrg)] {
					return false
				}
			} else if !strings.EqualFold(eventOrg, sub.Organization) {
				// Specific org - must match
				return false
			}
		} else {
			// No org specified - check user is member of the event's org
			if eventOrg != "" && !userOrgs[strings.ToLower(eventOrg)] {
				return false
			}
		}
		// Check if user is involved in the event
		return matchesUser(sub.Username, payload)
	}

	// For regular subscription mode with org specified
	if sub.Organization != "" {
		// Handle wildcard organization - matches any org the user is a member of
		if sub.Organization == "*" {
			// Check if the event org is one the user is a member of
			// If event has no org info (eventOrg == ""), don't match for security
			// (we can't verify user has permission to see events without org context)
			return eventOrg != "" && userOrgs[strings.ToLower(eventOrg)]
		}
		// Case-insensitive org name comparison
		return strings.EqualFold(eventOrg, sub.Organization)
	}

	// No matching mode found
	return false
}

// matchesUserInObject checks if username matches login in a user object.
func matchesUserInObject(user map[string]any, username string) bool {
	login, ok := user["login"].(string)
	return ok && strings.EqualFold(login, username)
}

// checkPullRequestUsers checks PR author, assignees, and reviewers.
func checkPullRequestUsers(pr map[string]any, username string) bool {
	// Check PR author
	if user, ok := pr["user"].(map[string]any); ok {
		if matchesUserInObject(user, username) {
			return true
		}
	}

	// Check assignees
	if assignees, ok := pr["assignees"].([]any); ok {
		for _, item := range assignees {
			if user, ok := item.(map[string]any); ok {
				if matchesUserInObject(user, username) {
					return true
				}
			}
		}
	}

	// Check requested reviewers
	if reviewers, ok := pr["requested_reviewers"].([]any); ok {
		for _, item := range reviewers {
			if user, ok := item.(map[string]any); ok {
				if matchesUserInObject(user, username) {
					return true
				}
			}
		}
	}

	return false
}

// checkCommentMention checks if username is mentioned in comment body.
func checkCommentMention(body, username string) bool {
	// Check for exact @username match (case-insensitive)
	bodyLower := strings.ToLower(body)
	mentionPrefix := "@" + strings.ToLower(username)
	idx := strings.Index(bodyLower, mentionPrefix)
	if idx < 0 {
		return false
	}

	// Check that it's not part of a longer username
	nextIdx := idx + len(mentionPrefix)
	if nextIdx >= len(bodyLower) {
		return true
	}

	nextChar := bodyLower[nextIdx]
	return (nextChar < 'a' || nextChar > 'z') && (nextChar < '0' || nextChar > '9') && nextChar != '-'
}

func matchesUser(username string, payload map[string]any) bool {
	// Check PR author, assignees, and reviewers
	if pr, ok := payload["pull_request"].(map[string]any); ok {
		if checkPullRequestUsers(pr, username) {
			return true
		}
	}

	// Check review author
	if review, ok := payload["review"].(map[string]any); ok {
		if user, ok := review["user"].(map[string]any); ok {
			if matchesUserInObject(user, username) {
				return true
			}
		}
	}

	// Check comment author and mentions
	if comment, ok := payload["comment"].(map[string]any); ok {
		if user, ok := comment["user"].(map[string]any); ok {
			if matchesUserInObject(user, username) {
				return true
			}
		}

		// Check mentions in comment body
		if body, ok := comment["body"].(string); ok {
			if checkCommentMention(body, username) {
				return true
			}
		}
	}

	// Check sender (action performer)
	if sender, ok := payload["sender"].(map[string]any); ok {
		if matchesUserInObject(sender, username) {
			return true
		}
	}

	return false
}
