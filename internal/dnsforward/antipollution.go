package dnsforward

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

func (s *Server) processUpstreamAntiPollution(
	ctx context.Context,
	l *slog.Logger,
	dctx *dnsContext,
) (rc resultCode) {
	l.DebugContext(ctx, "started processing anti-pollution")
	defer l.DebugContext(ctx, "finished processing anti-pollution")

	pctx := dctx.proxyCtx
	host := strings.TrimSuffix(pctx.Req.Question[0].Name, ".")

	ups := s.effectiveUpstreamsForAP(pctx)
	if len(ups) == 0 {
		l.DebugContext(ctx, "anti-pollution: no effective upstreams, falling back to normal resolution")

		return s.resolveNormally(ctx, l, dctx)
	}

	trusted, untrusted := splitUpstreamsByTrust(ups)

	if len(trusted) == 0 {
		l.WarnContext(ctx, "anti-pollution: no trusted upstreams configured")

		return s.resolveWithGroup(ctx, l, dctx, untrusted)
	}
	if len(untrusted) == 0 {
		return s.resolveWithGroup(ctx, l, dctx, trusted)
	}

	s.ensureAPCaches()

	inBlacklist := domainMatchesWildcard(host, s.conf.DomainBlacklist)
	inWhitelist := domainMatchesWildcard(host, s.conf.DomainWhitelist)

	l.DebugContext(ctx, "anti-pollution domain filter",
		"host", host,
		"in_blacklist", inBlacklist,
		"in_whitelist", inWhitelist,
	)

	switch {
	case inWhitelist && inBlacklist, inBlacklist:
		l.DebugContext(ctx, "anti-pollution: chose trusted (domain in blacklist)")

		return s.resolveWithGroup(ctx, l, dctx, trusted)
	case inWhitelist:
		l.DebugContext(ctx, "anti-pollution: chose untrusted (domain in whitelist)")

		return s.resolveWithGroup(ctx, l, dctx, untrusted)
	default:
		return s.processAntiPollutionSequential(ctx, l, dctx)
	}
}

// processAntiPollutionSequential resolves by trying untrusted upstreams first
// via prx.Resolve (which handles caching automatically), checking IP whitelist
// and blacklist, then falling back to trusted upstreams if needed.
//
// Each upstream group is queried at most once.  All results are cached by the
// proxy so subsequent requests for the same domain are served from cache with
// zero upstream latency.
func (s *Server) processAntiPollutionSequential(
	ctx context.Context,
	l *slog.Logger,
	dctx *dnsContext,
) (rc resultCode) {
	prx := s.proxy()
	if prx == nil {
		dctx.err = srvClosedErr

		return resultCodeError
	}

	host := strings.TrimSuffix(dctx.proxyCtx.Req.Question[0].Name, ".")

	// Try untrusted upstreams first.  prx.Resolve will check the untrusted
	// cache, and if it's a miss, query the upstream and cache the result.
	prevCustom := dctx.proxyCtx.CustomUpstreamConfig
	dctx.proxyCtx.CustomUpstreamConfig = s.apUntrustedUC

	if dctx.err = prx.Resolve(ctx, dctx.proxyCtx); dctx.err == nil {
		ips := extractIPsFromMsg(dctx.proxyCtx.Res)

		l.DebugContext(ctx, "anti-pollution ip filter",
			"host", host,
			"untrusted_ips", ipStrings(ips),
		)

		// IP blacklist has highest priority: blocked IPs are never returned.
		if ipMatchesAny(ips, s.conf.IPBlacklist) {
			l.DebugContext(ctx, "anti-pollution: untrusted response blocked (ip in blacklist)",
				"host", host,
				"ips", ipStrings(ips),
			)

			// Fall through to trusted.
		} else if ipMatchesAny(ips, s.conf.IPWhitelist) {
			l.DebugContext(ctx, "anti-pollution: chose untrusted (ip in whitelist)",
				"host", host,
				"ips", ipStrings(ips),
			)

			dctx.responseFromUpstream = true
			dctx.responseAD = dctx.proxyCtx.Res.AuthenticatedData
			dctx.proxyCtx.CustomUpstreamConfig = prevCustom

			return resultCodeSuccess
		} else {
			l.DebugContext(ctx, "anti-pollution: untrusted ip not in whitelist, trying trusted",
				"host", host,
				"ips", ipStrings(ips),
			)
		}
	} else {
		l.DebugContext(ctx, "anti-pollution: untrusted exchange failed",
			"host", host,
			"err", dctx.err,
		)
	}

	dctx.proxyCtx.CustomUpstreamConfig = prevCustom

	// Try trusted upstreams.
	dctx.proxyCtx.CustomUpstreamConfig = s.apTrustedUC
	if dctx.err = prx.Resolve(ctx, dctx.proxyCtx); dctx.err == nil {
		l.DebugContext(ctx, "anti-pollution: chose trusted",
			"host", host,
		)

		dctx.responseFromUpstream = true
		dctx.responseAD = dctx.proxyCtx.Res.AuthenticatedData
		dctx.proxyCtx.CustomUpstreamConfig = prevCustom

		return resultCodeSuccess
	}

	dctx.proxyCtx.CustomUpstreamConfig = prevCustom

	l.DebugContext(ctx, "anti-pollution: both upstream groups failed",
		"host", host,
	)

	return resultCodeError
}

// ensureAPCaches initializes the persistent CustomUpstreamConfig instances for
// anti-pollution mode.  They hold independent caches so repeated queries for
// the same domain are served from memory without contacting the upstream.
//
// Must be called with s.serverLock held to avoid racing with Reconfigure.
func (s *Server) ensureAPCaches() {
	if s.apTrustedUC != nil {
		return
	}

	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	if s.apTrustedUC != nil {
		return
	}

	// Read config while holding the lock to avoid racing with Reconfigure.
	cfg := s.conf
	if cfg.UpstreamConfig == nil {
		return
	}

	trustedUps, untrustedUps := splitUpstreamsByTrust(cfg.UpstreamConfig.Upstreams)

	ednsEnabled := false
	if cfg.EDNSClientSubnet != nil {
		ednsEnabled = cfg.EDNSClientSubnet.Enabled
	}

	if len(trustedUps) > 0 {
		s.apTrustedUC = proxy.NewCustomUpstreamConfig(
			&proxy.UpstreamConfig{Upstreams: trustedUps},
			cfg.CacheEnabled,
			int(cfg.CacheSize),
			ednsEnabled,
		)
	}

	if len(untrustedUps) > 0 {
		s.apUntrustedUC = proxy.NewCustomUpstreamConfig(
			&proxy.UpstreamConfig{Upstreams: untrustedUps},
			cfg.CacheEnabled,
			int(cfg.CacheSize),
			ednsEnabled,
		)
	}
}

// resolveWithGroup routes resolution through the built-in proxy path, using
// the persistent CustomUpstreamConfig with a shared cache.  The result is
// cached and subsequent requests for the same domain are served from cache.
func (s *Server) resolveWithGroup(
	ctx context.Context,
	_ *slog.Logger,
	dctx *dnsContext,
	ups []upstream.Upstream,
) (rc resultCode) {
	prx := s.proxy()
	if prx == nil {
		dctx.err = srvClosedErr

		return resultCodeError
	}

	var customUC *proxy.CustomUpstreamConfig
	if len(ups) > 0 && UpstreamTrusted(ups[0]) {
		customUC = s.apTrustedUC
	} else {
		customUC = s.apUntrustedUC
	}

	prevCustom := dctx.proxyCtx.CustomUpstreamConfig
	dctx.proxyCtx.CustomUpstreamConfig = customUC

	if dctx.err = prx.Resolve(ctx, dctx.proxyCtx); dctx.err != nil {
		dctx.proxyCtx.CustomUpstreamConfig = prevCustom

		return resultCodeError
	}

	dctx.responseFromUpstream = true
	dctx.responseAD = dctx.proxyCtx.Res.AuthenticatedData

	dctx.proxyCtx.CustomUpstreamConfig = prevCustom

	return resultCodeSuccess
}

// effectiveUpstreamsForAP returns the effective upstreams for anti-pollution
// mode.  If the client has a custom upstream config, nil is returned and the
// caller should fall back to normal resolution.
func (s *Server) effectiveUpstreamsForAP(pctx *proxy.DNSContext) (ups []upstream.Upstream) {
	if pctx.CustomUpstreamConfig != nil {
		return nil
	}

	if s.conf.UpstreamConfig == nil {
		return nil
	}

	return s.conf.UpstreamConfig.Upstreams
}

// splitUpstreamsByTrust splits the given upstreams into trusted and untrusted
// groups.
func splitUpstreamsByTrust(ups []upstream.Upstream) (trusted, untrusted []upstream.Upstream) {
	for _, u := range ups {
		if UpstreamTrusted(u) {
			trusted = append(trusted, u)
		} else {
			untrusted = append(untrusted, u)
		}
	}

	return trusted, untrusted
}

// resolveNormally falls back to normal proxy resolution.  This path is taken
// when the client has a custom upstream config that overrides the global
// anti-pollution settings.
func (s *Server) resolveNormally(
	ctx context.Context,
	l *slog.Logger,
	dctx *dnsContext,
) (rc resultCode) {
	l.DebugContext(ctx, "anti-pollution: falling back to normal resolution (client has custom upstreams)")

	prx := s.proxy()
	if prx == nil {
		dctx.err = srvClosedErr

		return resultCodeError
	}

	if dctx.err = prx.Resolve(ctx, dctx.proxyCtx); dctx.err != nil {
		return resultCodeError
	}

	dctx.responseFromUpstream = true
	dctx.responseAD = dctx.proxyCtx.Res.AuthenticatedData

	return resultCodeSuccess
}

// domainMatchesWildcard checks if host matches any pattern in the list.
// Patterns support:
//   - Plain domain (e.g. "example.org") matches the domain itself and all
//     subdomains (e.g. "www.example.org", "a.b.example.org").
//   - Wildcard prefix (e.g. "*.example.org") matches only subdomains,
//     NOT the domain itself.
func domainMatchesWildcard(host string, patterns []string) (matched bool) {
	if len(patterns) == 0 {
		return false
	}

	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || p[0] == '#' {
			continue
		}

		if domainMatchesPattern(host, p) {
			return true
		}
	}

	return false
}

// domainMatchesPattern checks if host matches a single pattern.
// Domain matching is case-insensitive per DNS standards (RFC 4343).
//
// Pattern semantics:
//   - "*.example.org": matches subdomains only (e.g. "www.example.org"),
//     does NOT match "example.org" itself.
//   - "example.org": matches the domain itself AND all subdomains
//     (e.g. "example.org", "www.example.org", "a.b.example.org").
func domainMatchesPattern(host, pattern string) (ok bool) {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]

		return strings.HasSuffix(host, suffix)
	}

	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

// ipMatchesAny checks if any IP in addrs matches any pattern in the list.
// Patterns can be single IP addresses or CIDR prefixes.
func ipMatchesAny(addrs []netip.Addr, patterns []string) (matched bool) {
	if len(patterns) == 0 || len(addrs) == 0 {
		return false
	}

	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || p[0] == '#' {
			continue
		}

		for _, a := range addrs {
			if ipMatchesPattern(a, p) {
				return true
			}
		}
	}

	return false
}

// ipMatchesPattern checks if addr matches a single IP or CIDR pattern.
func ipMatchesPattern(addr netip.Addr, pattern string) (ok bool) {
	if strings.Contains(pattern, "/") {
		prefix, err := netip.ParsePrefix(pattern)
		if err != nil {
			return false
		}

		return prefix.Contains(addr)
	}

	target, err := netip.ParseAddr(pattern)
	if err != nil {
		return false
	}

	return addr == target
}

// ipStrings formats ips for logging.
func ipStrings(ips []netip.Addr) (ss []string) {
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}

	return ss
}

// extractIPsFromMsg extracts all A and AAAA record IPs from a DNS response.
func extractIPsFromMsg(msg *dns.Msg) (ips []netip.Addr) {
	if msg == nil {
		return nil
	}

	for _, rr := range msg.Answer {
		switch a := rr.(type) {
		case *dns.A:
			ip, ok := netip.AddrFromSlice(a.A)
			if ok {
				ips = append(ips, ip)
			}
		case *dns.AAAA:
			ip, ok := netip.AddrFromSlice(a.AAAA)
			if ok {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// CloseAPCaches should be called when the server is shutting down or
// reconfiguring to close the anti-pollution caches and reset them to nil.
// The caller must hold s.serverLock.
func (s *Server) CloseAPCaches() {
	var wg sync.WaitGroup

	if s.apTrustedUC != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.apTrustedUC.Close()
		}()
	}

	if s.apUntrustedUC != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.apUntrustedUC.Close()
		}()
	}

	wg.Wait()

	s.apTrustedUC = nil
	s.apUntrustedUC = nil
}