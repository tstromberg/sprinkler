package gitlab

import (
	"context"
	"errors"
	"sync"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
)

// MockClient is a mock GitLab API client for testing.
// Thread-safe for concurrent access.
//
//nolint:govet // fieldalignment: minimal impact, current order is logical
type MockClient struct {
	Groups                     []string
	Err                        error
	Username                   string
	LastValidatedGroup         string
	Tier                       github.Tier // Mock tier to return
	mu                         sync.Mutex
	UserAndOrgsCalls           int
	ValidateOrgMembershipCalls int
	UserTierCalls              int
}

// UserAndOrgs returns the mock user info.
func (m *MockClient) UserAndOrgs(_ context.Context) (username string, orgs []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UserAndOrgsCalls++
	if m.Err != nil {
		return "", nil, m.Err
	}
	return m.Username, m.Groups, nil
}

// ValidateOrgMembership validates group membership using the mock data.
func (m *MockClient) ValidateOrgMembership(_ context.Context, org string) (username string, orgs []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ValidateOrgMembershipCalls++
	m.LastValidatedGroup = org

	if m.Err != nil {
		return "", nil, m.Err
	}

	// Check if user is member of the requested group
	isMember := false
	for _, userGroup := range m.Groups {
		if userGroup == org {
			isMember = true
			break
		}
	}

	if !isMember {
		return m.Username, m.Groups, errors.New("not a member of group " + org)
	}

	return m.Username, m.Groups, nil
}

// UserTier returns the mock tier.
func (m *MockClient) UserTier(_ context.Context, _ string) (github.Tier, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UserTierCalls++
	if m.Err != nil {
		return github.TierFree, m.Err
	}
	// If no tier is set, default to TierFlock (GitLab users get full access)
	if m.Tier == "" {
		return github.TierFlock, nil
	}
	return m.Tier, nil
}

// Ensure MockClient implements github.APIClient interface.
var _ github.APIClient = (*MockClient)(nil)
