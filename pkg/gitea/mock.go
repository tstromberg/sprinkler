package gitea

import (
	"context"
	"errors"
	"sync"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
)

// MockClient is a mock Gitea API client for testing.
// Thread-safe for concurrent access.
//
//nolint:govet // fieldalignment: minimal impact, current order is logical
type MockClient struct {
	Orgs                       []string
	Err                        error
	Username                   string
	LastValidatedOrg           string
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
	return m.Username, m.Orgs, nil
}

// ValidateOrgMembership validates organization membership using the mock data.
func (m *MockClient) ValidateOrgMembership(_ context.Context, org string) (username string, orgs []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ValidateOrgMembershipCalls++
	m.LastValidatedOrg = org

	if m.Err != nil {
		return "", nil, m.Err
	}

	// Check if user is member of the requested org
	isMember := false
	for _, userOrg := range m.Orgs {
		if userOrg == org {
			isMember = true
			break
		}
	}

	if !isMember {
		return m.Username, m.Orgs, errors.New("not a member of organization " + org)
	}

	return m.Username, m.Orgs, nil
}

// UserTier returns the mock tier.
func (m *MockClient) UserTier(_ context.Context, _ string) (github.Tier, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UserTierCalls++
	if m.Err != nil {
		return github.TierFlock, m.Err
	}
	// If no tier is set, default to TierFlock (Gitea users get full access)
	if m.Tier == "" {
		return github.TierFlock, nil
	}
	return m.Tier, nil
}

// Ensure MockClient implements github.APIClient interface.
var _ github.APIClient = (*MockClient)(nil)
