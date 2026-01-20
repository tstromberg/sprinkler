// Package gitlab provides client functionality for interacting with the GitLab API,
// including user authentication and group validation.
package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
)

const (
	clientTimeout = 10 * time.Second
)

// Client provides GitLab API functionality.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	token      string
	baseURL    string // Base URL for GitLab instance (e.g., https://gitlab.com)
}

// NewClient creates a new GitLab API client with the provided token and base URL.
// If logger is nil, a default discarding logger is used.
// If baseURL is empty, defaults to https://gitlab.com.
func NewClient(token, baseURL string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	// Remove trailing slash for consistency
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Client{
		httpClient: &http.Client{
			Timeout: clientTimeout,
		},
		token:   token,
		baseURL: baseURL,
		logger:  logger,
	}
}

// User represents a GitLab user.
type User struct {
	Username string `json:"username"`
	ID       int    `json:"id"`
}

// Group represents a GitLab group (similar to GitHub organization).
type Group struct {
	FullPath string `json:"full_path"`
	ID       int    `json:"id"`
}

// AuthenticatedUser returns the currently authenticated user's info.
func (c *Client) AuthenticatedUser(ctx context.Context) (*User, error) {
	var user *User
	var lastErr error

	url := fmt.Sprintf("%s/api/v4/user", c.baseURL)

	err := retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("GitLab API request failed (will retry)", "error", err)
				return err
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					c.logger.Warn("failed to close response body", "error", err)
				}
			}()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
			if err != nil {
				lastErr = fmt.Errorf("failed to read response: %w", err)
				return err
			}

			switch resp.StatusCode {
			case http.StatusOK:
				var u User
				if err := json.Unmarshal(body, &u); err != nil {
					return retry.Unrecoverable(fmt.Errorf("failed to parse user response: %w", err))
				}
				if u.Username == "" {
					return retry.Unrecoverable(errors.New("no username found in response"))
				}
				user = &u
				return nil

			case http.StatusUnauthorized:
				c.logger.Warn("GitLab API: 401 Unauthorized - invalid token for /user endpoint")
				return retry.Unrecoverable(errors.New("invalid GitLab token"))

			case http.StatusForbidden:
				c.logger.Warn("GitLab API: 403 Forbidden - access denied for /user endpoint")
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				lastErr = fmt.Errorf("GitLab API server error: %d", resp.StatusCode)
				c.logger.Warn("GitLab API server error (will retry)", "status", resp.StatusCode)
				return lastErr

			default:
				return retry.Unrecoverable(fmt.Errorf("unexpected status: %d", resp.StatusCode))
			}
		},
		retry.Attempts(3),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.Context(ctx),
	)
	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}

	return user, nil
}

// UserAndOrgs retrieves the authenticated user's username and list of groups.
// Returns username, list of group names, and error.
func (c *Client) UserAndOrgs(ctx context.Context) (username string, orgs []string, err error) {
	c.logger.Info("GitLab API: Starting authentication")

	// Get authenticated user
	user, err := c.AuthenticatedUser(ctx)
	if err != nil {
		c.logger.Warn("GitLab API: Failed to get authenticated user", "error", err)
		return "", nil, fmt.Errorf("failed to get authenticated user: %w", err)
	}
	c.logger.Info("GitLab API: Successfully authenticated as user", "user", user.Username)

	// Get user's groups
	groupList, err := c.userGroups(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Build list of group names
	groupNames := make([]string, len(groupList))
	for i, g := range groupList {
		groupNames[i] = g.FullPath
	}

	c.logger.Info("GitLab API: User groups loaded", "user", user.Username, "group_count", len(groupList))
	return user.Username, groupNames, nil
}

// userGroups fetches all groups the authenticated user is a member of.
func (c *Client) userGroups(ctx context.Context) ([]Group, error) {
	var groups []Group
	var lastErr error

	url := fmt.Sprintf("%s/api/v4/groups?min_access_level=10", c.baseURL) // 10 = Guest access

	c.logger.Debug("GitLab API: Fetching user's groups...")

	err := retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("GitLab API group fetch failed (will retry)", "error", err)
				return err
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					c.logger.Warn("failed to close response body", "error", err)
				}
			}()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
			if err != nil {
				lastErr = fmt.Errorf("failed to read response: %w", err)
				return err
			}

			switch resp.StatusCode {
			case http.StatusOK:
				if err := json.Unmarshal(body, &groups); err != nil {
					return retry.Unrecoverable(fmt.Errorf("failed to parse groups response: %w", err))
				}
				return nil

			case http.StatusUnauthorized:
				c.logger.Warn("GitLab API: 401 Unauthorized - invalid token for /groups endpoint")
				return retry.Unrecoverable(errors.New("invalid GitLab token"))

			case http.StatusForbidden:
				c.logger.Warn("GitLab API: 403 Forbidden - access denied for /groups endpoint")
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				lastErr = fmt.Errorf("GitLab API server error: %d", resp.StatusCode)
				c.logger.Warn("GitLab API server error (will retry)", "status", resp.StatusCode)
				return lastErr

			default:
				return retry.Unrecoverable(fmt.Errorf("unexpected response status: %d", resp.StatusCode))
			}
		},
		retry.Attempts(3),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.Context(ctx),
	)
	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}

	return groups, nil
}

// ValidateOrgMembership checks if the authenticated user has access to the specified group.
// Returns the authenticated user's username, list of all their groups, and nil error if successful.
func (c *Client) ValidateOrgMembership(ctx context.Context, org string) (username string, orgs []string, err error) {
	c.logger.Debug("GitLab API: Starting authentication and group membership validation", "group", org)

	// Sanitize org name
	org = strings.TrimSpace(org)
	if org == "" {
		return "", nil, errors.New("group name cannot be empty")
	}

	// Get user and all their groups
	username, groupNames, err := c.UserAndOrgs(ctx)
	if err != nil {
		return "", nil, err
	}

	// Check if the requested group is in the user's membership list
	for _, userGroup := range groupNames {
		if strings.EqualFold(userGroup, org) {
			c.logger.Info("GitLab API: User is a member of group", "user", username, "group", org, "total_groups", len(groupNames))
			return username, groupNames, nil
		}
	}

	// User is not a member of the requested group
	c.logger.Warn("GitLab API: User is NOT a member of group", "user", username, "group", org, "member_groups", groupNames)
	return username, groupNames, errors.New("user is not a member of the requested group")
}

// UserTier fetches the user's GitLab subscription tier.
// GitLab has Free, Premium, and Ultimate tiers.
// Maps to: Free -> TierFree, Premium/Ultimate -> TierFlock.
func (c *Client) UserTier(ctx context.Context, username string) (github.Tier, error) {
	if username == "" {
		return github.TierFree, errors.New("username cannot be empty")
	}

	// For GitLab, we could query the user's namespace to get tier info
	// However, GitLab's API doesn't expose tier information for all instances
	// For now, we'll return TierFlock (full access) for simplicity
	// This can be enhanced later if needed

	c.logger.Info("GitLab API: Tier detection", "username", username, "tier", github.TierFlock, "note", "GitLab users default to Flock tier")
	return github.TierFlock, nil
}
