# webhook-sprinkler

<div align="center">
  <img src="media/logo-small.png" alt="webhook-sprinkler logo" width="300">
</div>

<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/codeGROOVE-dev/sprinkler.svg)](https://pkg.go.dev/github.com/codeGROOVE-dev/sprinkler)
[![Go Report Card](https://goreportcard.com/badge/github.com/codeGROOVE-dev/sprinkler)](https://goreportcard.com/report/github.com/codeGROOVE-dev/sprinkler)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/github/go-mod/go-version/codeGROOVE-dev/sprinkler)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/codeGROOVE-dev/sprinkler?include_prereleases)](https://github.com/codeGROOVE-dev/sprinkler/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/codeGROOVE-dev/sprinkler/pulls)

</div>

Git platforms (GitHub, GitLab, Gitea, Gitee) only allow one webhook endpoint per app. This service multiplexes that single webhook into authenticated WebSocket connections, so multiple clients can subscribe to just the events they care about.

## Features

- **Multi-platform support**: Works with GitHub, GitLab, Gitea, and Gitee (including self-hosted instances)
- **Flexible subscriptions**: Subscribe to specific PRs/MRs, organizations/groups, or all your events
- **Secure**: Token-based authentication with webhook signature verification
- **Scalable**: Handles thousands of concurrent WebSocket connections
- **Real-time**: Instant event delivery to subscribers

## Quick start

```bash
export GITHUB_WEBHOOK_SECRET="your-webhook-secret"
go run ./cmd/server
go run ./cmd/client
```

## Client examples

**Important**: All clients must provide a User-Agent header in the format `client-name/version` (e.g., `myapp/v1.0.0`). Connections without a valid User-Agent will be rejected with a 400 Bad Request error.

### GitHub - Subscribe to organization events
```javascript
const ws = new WebSocket('wss://your-server/ws', {
  headers: {
    'Authorization': 'Bearer ghp_your_github_token',
    'User-Agent': 'myapp/v1.0.0'
  }
});

ws.on('open', () => {
  ws.send(JSON.stringify({
    platform: "github",  // Optional, defaults to github
    organization: "your-org",
    event_types: ["pull_request"]
  }));
});

ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log(`${event.type}: ${event.url}`);
});
```

### GitLab - Subscribe to group events
```javascript
const ws = new WebSocket('wss://your-server/ws', {
  headers: {
    'Authorization': 'Bearer glpat-your_gitlab_token',
    'User-Agent': 'myapp/v1.0.0'
  }
});

ws.on('open', () => {
  ws.send(JSON.stringify({
    platform: "gitlab",
    organization: "your-group",  // GitLab group
    event_types: ["Merge Request Hook"]
  }));
});
```

### Gitea/Codeberg - Subscribe to organization events
```javascript
const ws = new WebSocket('wss://your-server/ws', {
  headers: {
    'Authorization': 'Bearer your_gitea_token',
    'User-Agent': 'myapp/v1.0.0'
  }
});

ws.on('open', () => {
  ws.send(JSON.stringify({
    platform: "gitea",
    organization: "your-org",
    event_types: ["pull_request"]
  }));
});
```

### Gitee - Subscribe to organization events
```javascript
const ws = new WebSocket('wss://your-server/ws', {
  headers: {
    'Authorization': 'Bearer your_gitee_token',
    'User-Agent': 'myapp/v1.0.0'
  }
});

ws.on('open', () => {
  ws.send(JSON.stringify({
    platform: "gitee",
    organization: "your-org",
    event_types: ["pull_request"]
  }));
});
```

### Self-hosted instances
```javascript
// Self-hosted GitHub Enterprise
ws.send(JSON.stringify({
  platform: "github",
  base_url: "https://github.company.com",
  organization: "your-org"
}));

// Self-hosted GitLab
ws.send(JSON.stringify({
  platform: "gitlab",
  base_url: "https://gitlab.company.com",
  organization: "your-group"
}));

// Custom Gitea instance
ws.send(JSON.stringify({
  platform: "gitea",
  base_url: "https://git.company.com",
  organization: "your-org"
}));

// Self-hosted Gitee
ws.send(JSON.stringify({
  platform: "gitee",
  base_url: "https://gitee.company.com",
  organization: "your-org"
}));
```

### Subscribe to your events across all organizations
```javascript
ws.on('open', () => {
  ws.send(JSON.stringify({
    user_events_only: true  // No organization required
  }));
});
```

### Subscribe to specific PRs/MRs
```javascript
// GitHub PRs
ws.send(JSON.stringify({
  platform: "github",
  pull_requests: [
    "https://github.com/your-org/repo/pull/123",
    "https://github.com/your-org/repo/pull/456"
  ]
}));

// GitLab MRs
ws.send(JSON.stringify({
  platform: "gitlab",
  pull_requests: [
    "https://gitlab.com/your-group/repo/-/merge_requests/123"
  ]
}));

// Gitea PRs
ws.send(JSON.stringify({
  platform: "gitea",
  pull_requests: [
    "https://codeberg.org/your-org/repo/pulls/123"
  ]
}));

// Gitee PRs
ws.send(JSON.stringify({
  platform: "gitee",
  pull_requests: [
    "https://gitee.com/your-org/repo/pulls/123"
  ]
}));
```

**Note**: You can subscribe to up to 200 PRs/MRs per connection, and you must be a member of the organization/group that owns them.

### Command-line client examples
```bash
# Subscribe to organization events
go run ./cmd/client -org your-org

# Subscribe to specific PRs (no org required)
go run ./cmd/client -prs "https://github.com/your-org/repo/pull/123,https://github.com/your-org/repo/pull/456"

# Subscribe to your events across all organizations
go run ./cmd/client --user

# Combine filters
go run ./cmd/client -org your-org -user  # Your events in a specific org
```

## Configuration

```bash
-webhook-secret="..."        # Webhook secret (required, same for all platforms)
-allowed-events="..."        # Event types to allow or "*" for all
-max-conns-per-ip=10         # WebSocket connections per IP
-max-conns-total=1000        # Total WebSocket connections
-enforce-tiers               # Enforce tier restrictions (default: false)
-letsencrypt                 # Auto HTTPS via Let's Encrypt
-le-domains="..."            # Your domain(s)
```

## Tokens

### GitHub
- Personal Access Tokens (classic or fine-grained)
- Format: `ghp_...` or `github_pat_...`
- Scopes needed: `repo`, `read:org`

### GitLab
- Personal Access Tokens or Project Access Tokens
- Format: `glpat-...` or custom
- Scopes needed: `api`, `read_api`

### Gitea/Codeberg
- Application tokens or access tokens
- No specific format required
- Scopes: Full API access

### Gitee
- Personal Access Tokens
- No specific format required
- Scopes: Full API access

## How it works

1. Git platform sends webhook to this service
2. Service detects platform and verifies signature:
   - GitHub: HMAC-SHA256 (X-Hub-Signature-256)
   - GitLab: Token comparison (X-Gitlab-Token)
   - Gitea: HMAC-SHA256 (X-Gitea-Signature)
   - Gitee: HMAC-SHA256 (X-Gitee-Token)
3. Broadcasts event to WebSocket clients that:
   - Have valid platform tokens
   - Are members of the event's organization/group
   - Have subscribed to that event type

## Development

```bash
make test       # Run tests
make fmt        # Format code
make lint       # Run linter
```
