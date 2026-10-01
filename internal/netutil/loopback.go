// Package netutil holds small shared network helpers used by node and pool packages.
package netutil

import (
	"net"
	"net/url"
	"strings"
)

// IsLoopbackHost reports whether host is a loopback name or address.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.Trim(host, "[]")
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// IsLoopbackURL reports whether u's hostname is loopback (http/https URLs).
// Unlike substring Contains checks, hosts like 127.0.0.1.attacker.example are NOT loopback.
// Userinfo is rejected: forms like http://127.0.0.1:8080@evil.example dial evil.example
// while a naive string-slicer can mis-read the userinfo as the host (report #24).
func IsLoopbackURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.User != nil && u.User.String() != "" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		// bare host:port without scheme
		if h, _, err := net.SplitHostPort(raw); err == nil {
			host = h
		} else {
			host = raw
		}
	}
	return IsLoopbackHost(host)
}

// LooksRemoteCoordinatorURL is the inverse of IsLoopbackURL for empty-safe checks.
func LooksRemoteCoordinatorURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	return !IsLoopbackURL(raw)
}

// SafeHTTPBaseURL reports whether raw is an http(s) URL with a host and no userinfo.
// Used for coordinator / settle bases so credentials are never dialed to userinfo hosts.
func SafeHTTPBaseURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.User != nil && u.User.String() != "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}
