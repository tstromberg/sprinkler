package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrURLNotHTTPS is returned when URL doesn't use HTTPS.
	ErrURLNotHTTPS = errors.New("URL must use HTTPS")

	// ErrInternalIP is returned when URL resolves to an internal/private IP address.
	ErrInternalIP = errors.New("URL cannot point to internal addresses")
)

// BlockInternalIPs checks if a URL resolves to internal/private IP addresses.
// Uses Go's built-in IP classification functions (IsPrivate, IsLoopback, etc.).
// This prevents SSRF attacks against internal services and cloud metadata endpoints.
func BlockInternalIPs(ctx context.Context, rawURL string) error {
	// Enforce HTTPS only
	if !strings.HasPrefix(rawURL, "https://") {
		return ErrURLNotHTTPS
	}

	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("URL must have a hostname")
	}

	// Block localhost by name
	if strings.Contains(strings.ToLower(host), "localhost") {
		return fmt.Errorf("%w: localhost not allowed", ErrInternalIP)
	}

	// Resolve hostname to IPs
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %w", err)
	}

	// Check all resolved IPs
	for _, ip := range ips {
		// Use Go's built-in IP classification
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("%w: %s resolves to internal IP %s", ErrInternalIP, host, ip)
		}

		// Explicitly block cloud metadata endpoints
		ipStr := ip.String()
		if ipStr == "169.254.169.254" || ipStr == "169.254.170.2" || ipStr == "fd00:ec2::254" {
			return fmt.Errorf("%w: %s resolves to cloud metadata endpoint", ErrInternalIP, host)
		}
	}

	return nil
}
