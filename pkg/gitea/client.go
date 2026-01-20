// Package gitea provides client functionality for interacting with the Gitea API,
// including user authentication and organization validation.
package gitea

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

// Client provides Gitea API functionality.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	token      string
	baseURL    string // Base URL for Gitea instance (e.g., https://codeberg.org)
}

// NewClient creates a new Gitea API client with the provided token and base URL.
// If logger is nil, a default discarding logger is used.
// If baseURL is empty, defaults to https://codeberg.org.
func NewClient(token, baseURL string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if baseURL == "" {
		baseURL = "https://codeberg.org"
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

// User represents a Gitea user.
type User struct {
	Username string `json:"username"`
	Login    string `json:"login"` // Gitea API uses 'login' as the primary username field
	ID       int    `json:"id"`
}

// Organization represents a Gitea organization.
type Organization struct {
	Username string `json:"username"`
	ID       int    `json:"id"`
}

// AuthenticatedUser returns the currently authenticated user's info.
func (c *Client) AuthenticatedUser(ctx context.Context) (*User, error) {
	var user *User
	var lastErr error

	url := fmt.Sprintf("%s/api/v1/user", c.baseURL)

	err := retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("Gitea API request failed (will retry)", "error", err)
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
				// Gitea uses 'login' as the primary username field
				if u.Login == "" && u.Username == "" {
					return retry.Unrecoverable(errors.New("no username found in response"))
				}
				if u.Login != "" {
					u.Username = u.Login
				}
				user = &u
				return nil

			case http.StatusUnauthorized:
				c.logger.Warn("Gitea API: 401 Unauthorized - invalid token for /user endpoint")
				return retry.Unrecoverable(errors.New("invalid Gitea token"))

			case http.StatusForbidden:
				c.logger.Warn("Gitea API: 403 Forbidden - access denied for /user endpoint")
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				lastErr = fmt.Errorf("Gitea API server error: %d", resp.StatusCode) //nolint:staticcheck // Gitea is a proper noun
				c.logger.Warn("Gitea API server error (will retry)", "status", resp.StatusCode)
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

// UserAndOrgs retrieves the authenticated user's username and list of organizations.
// Returns username, list of organization names, and error.
func (c *Client) UserAndOrgs(ctx context.Context) (username string, orgs []string, err error) {
	c.logger.Info("Gitea API: Starting authentication")

	// Get authenticated user
	user, err := c.AuthenticatedUser(ctx)
	if err != nil {
		c.logger.Warn("Gitea API: Failed to get authenticated user", "error", err)
		return "", nil, fmt.Errorf("failed to get authenticated user: %w", err)
	}
	c.logger.Info("Gitea API: Successfully authenticated as user", "user", user.Username)

	// Get user's organizations
	orgList, err := c.userOrganizations(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get user organizations: %w", err)
	}

	// Build list of org names
	orgNames := make([]string, len(orgList))
	for i, o := range orgList {
		orgNames[i] = o.Username
	}

	c.logger.Info("Gitea API: User organizations loaded", "user", user.Username, "org_count", len(orgList))
	return user.Username, orgNames, nil
}

// userOrganizations fetches all organizations the authenticated user is a member of.
func (c *Client) userOrganizations(ctx context.Context) ([]Organization, error) {
	var orgs []Organization
	var lastErr error

	url := fmt.Sprintf("%s/api/v1/user/orgs", c.baseURL)

	c.logger.Debug("Gitea API: Fetching user's organizations...")

	err := retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("Gitea API org fetch failed (will retry)", "error", err)
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
				if err := json.Unmarshal(body, &orgs); err != nil {
					return retry.Unrecoverable(fmt.Errorf("failed to parse organizations response: %w", err))
				}
				return nil

			case http.StatusUnauthorized:
				c.logger.Warn("Gitea API: 401 Unauthorized - invalid token for /user/orgs endpoint")
				return retry.Unrecoverable(errors.New("invalid Gitea token"))

			case http.StatusForbidden:
				c.logger.Warn("Gitea API: 403 Forbidden - access denied for /user/orgs endpoint")
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				lastErr = fmt.Errorf("Gitea API server error: %d", resp.StatusCode) //nolint:staticcheck // Gitea is a proper noun
				c.logger.Warn("Gitea API server error (will retry)", "status", resp.StatusCode)
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

	return orgs, nil
}

// ValidateOrgMembership checks if the authenticated user has access to the specified organization.
// Returns the authenticated user's username, list of all their organizations, and nil error if successful.
func (c *Client) ValidateOrgMembership(ctx context.Context, org string) (username string, orgs []string, err error) {
	c.logger.Debug("Gitea API: Starting authentication and org membership validation", "org", org)

	// Sanitize org name
	org = strings.TrimSpace(org)
	if org == "" {
		return "", nil, errors.New("organization name cannot be empty")
	}

	// Get user and all their organizations
	username, orgNames, err := c.UserAndOrgs(ctx)
	if err != nil {
		return "", nil, err
	}

	// Check if the requested organization is in the user's membership list
	for _, userOrg := range orgNames {
		if strings.EqualFold(userOrg, org) {
			c.logger.Info("Gitea API: User is a member of organization", "user", username, "org", org, "total_orgs", len(orgNames))
			return username, orgNames, nil
		}
	}

	// User is not a member of the requested organization
	c.logger.Warn("Gitea API: User is NOT a member of organization", "user", username, "org", org, "member_orgs", orgNames)
	return username, orgNames, errors.New("user is not a member of the requested organization")
}

// UserTier fetches the user's subscription tier.
// Gitea/Codeberg are self-hosted or open platforms with no tiering, so always return TierFlock.
func (c *Client) UserTier(ctx context.Context, username string) (github.Tier, error) {
	if username == "" {
		return github.TierFlock, errors.New("username cannot be empty")
	}

	// Gitea/Codeberg instances don't have subscription tiers
	// All users get full access (TierFlock)
	c.logger.Info("Gitea API: Tier detection", "username", username, "tier", github.TierFlock, "note", "Gitea users always get Flock tier")
	return github.TierFlock, nil
}
