package aidr

import (
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Which site a request was meant for — the authority a signature must cover.
//
// A signature covers @authority, so the verifier must judge it against THIS site's own origin.
// The request's Host header is what the client sent: a request signed for another site, replayed
// here with that site's Host, would verify wherever the server answers any host name (found
// 2026-10-10). So the site says who it is, in Policy.PublicOrigins or AIDR_PUBLIC_ORIGIN
// (comma-separated). A request whose Host matches one is judged as that origin; any other Host as
// the first — so a signature made for a host that is not this site's never matches.
//
// Without an origin, localhost (and 127.0.0.0/8, ::1) still works, for development. Any other
// host: in 0.1.x a warning, once, and the Host header is used as before; from 0.2.0 an agent's
// request is refused (aidr.config.public_origin_required).

// PublicOriginEnv names the environment variable read when Policy.PublicOrigins is empty.
const PublicOriginEnv = "AIDR_PUBLIC_ORIGIN"

// EnforcePublicOrigin is true from 0.2.0 (refuse); 0.1.x warned.
var EnforcePublicOrigin = true

// CodePublicOriginRequired is returned when nothing says which site this is.
const CodePublicOriginRequired = "aidr.config.public_origin_required"

var originWarning sync.Once

// configuredOrigins returns the policy's origins, else the environment's; nil when neither.
func configuredOrigins(policy []string) ([]string, error) {
	raw := policy
	if len(raw) == 0 {
		if value := os.Getenv(PublicOriginEnv); value != "" {
			raw = strings.Split(value, ",")
		}
	}
	var origins []string
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			return nil, newError(CodePublicOriginRequired, "public origin is not an http(s) origin: "+value, nil)
		}
		origins = append(origins, parsed.Scheme+"://"+strings.ToLower(parsed.Host))
	}
	return origins, nil
}

// IsLoopbackHost reports localhost, *.localhost, 127.0.0.0/8 and ::1, with or without a port.
func IsLoopbackHost(host string) bool {
	name := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(name); err == nil {
		name = h
	}
	name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

// resolveOrigin returns "scheme://host" a request is judged as.
func resolveOrigin(configured []string, scheme, hostHeader string) (string, error) {
	origins, err := configuredOrigins(configured)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSpace(hostHeader))
	if len(origins) > 0 {
		for _, origin := range origins {
			if parsed, _ := url.Parse(origin); parsed != nil && parsed.Host == host {
				return origin, nil
			}
		}
		return origins[0], nil
	}
	if IsLoopbackHost(host) {
		return scheme + "://" + host, nil
	}
	if EnforcePublicOrigin {
		return "", newError(CodePublicOriginRequired,
			"this site has not configured its public origin (Policy.PublicOrigins or "+PublicOriginEnv+
				"), so agents cannot be verified", nil)
	}
	originWarning.Do(func() {
		log.Printf("[aidr] Policy.PublicOrigins is not set: requests are judged by their Host header, " +
			"which the client chooses. A request signed for another site could be replayed here. Set it " +
			"(or " + PublicOriginEnv + ") to this site's origin; from 0.2.0 it is required.")
	})
	return scheme + "://" + host, nil
}
