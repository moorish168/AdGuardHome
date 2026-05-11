package dnsforward

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// processUpstreamAntiPollution handles upstream resolution in anti-pollution
// mode.  It splits upstreams into trusted and untrusted groups, matches the
// domain against blacklist/whitelist, and applies IP-level filtering to choose
// the best result.
//
// The decision is made in a single pass with no retry loops, guaranteeing that
// the response never oscillates between trusted and untrusted upstreams.
//
// When the decision requires a trusted result but no trusted upstream is
// reachable, a SERVFAIL is returned to the client instead of falling back to
// possibly polluted untrusted data.
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

	inBlacklist := domainMatchesWildcard(host, s.conf.DomainBlacklist)
	inWhitelist := domainMatchesWildcard(host, s.conf.DomainWhitelist)

	l.DebugContext(ctx, "anti-pollution domain match",
		"host", host,
		"in_blacklist", inBlacklist,
		"in_whitelist", inWhitelist,
	)

	switch {
	case inWhitelist && inBlacklist, inBlacklist:
		return s.resolveWithGroup(ctx, l, dctx, trusted)
	case inWhitelist:
		return s.resolveWithGroup(ctx, l, dctx, untrusted)
	default:
		return s.processAntiPollutionBoth(ctx, l, dctx, trusted, untrusted)
	}
}

// processAntiPollutionBoth queries both trusted and untrusted upstreams in
// parallel, then applies IP-level blacklist/whitelist filtering on the
// untrusted result.
//
// Safety guarantees:
//   - If the IP filtering says trusted is required but trusted is unreachable,
//     a SERVFAIL is returned — the untrusted result is NEVER used as a
//     substitute.
//   - Each request makes exactly one decision pass; there is no retry loop
//     that could oscillate between trusted and untrusted upstreams.
func (s *Server) processAntiPollutionBoth(
	ctx context.Context,
	l *slog.Logger,
	dctx *dnsContext,
	trusted, untrusted []upstream.Upstream,
) (rc resultCode) {
	req := dctx.proxyCtx.Req

	type exchangeResult struct {
		resp *dns.Msg
		u    upstream.Upstream
		err  error
	}

	var (
		trustedRes   exchangeResult
		untrustedRes exchangeResult
	)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		trustedRes.resp, trustedRes.u, trustedRes.err = exchangeWithUpstreams(trusted, req)
	}()

	go func() {
		defer wg.Done()
		untrustedRes.resp, untrustedRes.u, untrustedRes.err = exchangeWithUpstreams(untrusted, req)
	}()

	wg.Wait()

	if trustedRes.err != nil {
		l.DebugContext(ctx, "trusted exchange failed", "err", trustedRes.err)
	}
	if untrustedRes.err != nil {
		l.DebugContext(ctx, "untrusted exchange failed", "err", untrustedRes.err)
	}

	untrustedOK := untrustedRes.resp != nil
	trustedOK := trustedRes.resp != nil

	if untrustedOK {
		ips := extractIPsFromMsg(untrustedRes.resp)
		ipInBlacklist := ipMatchesAny(ips, s.conf.IPBlacklist)
		ipInWhitelist := ipMatchesAny(ips, s.conf.IPWhitelist)

		l.DebugContext(ctx, "anti-pollution ip match",
			"ips", ips,
			"ip_in_blacklist", ipInBlacklist,
			"ip_in_whitelist", ipInWhitelist,
		)

		switch {
		case ipInBlacklist && ipInWhitelist:
			if trustedOK {
				s.setResponse(dctx, trustedRes.resp, trustedRes.u)

				return resultCodeSuccess
			}

			s.antiPollutionBlock(ctx, l, dctx, "both_blacklist_and_whitelist")

			return resultCodeFinish

		case ipInBlacklist:
			if trustedOK {
				s.setResponse(dctx, trustedRes.resp, trustedRes.u)

				return resultCodeSuccess
			}

			s.antiPollutionBlock(ctx, l, dctx, "ip_blacklist_trusted_unreachable")

			return resultCodeFinish

		case ipInWhitelist:
			s.setResponse(dctx, untrustedRes.resp, untrustedRes.u)

			return resultCodeSuccess

		default:
			s.setResponse(dctx, untrustedRes.resp, untrustedRes.u)

			return resultCodeSuccess
		}
	}

	if trustedOK {
		s.setResponse(dctx, trustedRes.resp, trustedRes.u)

		return resultCodeSuccess
	}

	dctx.err = fmt.Errorf(
		"all anti-pollution upstreams failed: trusted: %w, untrusted: %w",
		trustedRes.err,
		untrustedRes.err,
	)

	return resultCodeError
}

// antiPollutionBlock responds with SERVFAIL when the anti-pollution logic
// determines that a trusted upstream result is required but none is available.
// This prevents the client from caching a potentially polluted response from an
// untrusted upstream.
func (s *Server) antiPollutionBlock(
	ctx context.Context,
	l *slog.Logger,
	dctx *dnsContext,
	reason string,
) {
	l.WarnContext(ctx, "anti-pollution: blocked response to prevent pollution",
		"reason", reason,
		"question", dctx.proxyCtx.Req.Question[0].Name,
	)

	dctx.proxyCtx.Res = s.NewMsgSERVFAIL(dctx.proxyCtx.Req)
	dctx.responseFromUpstream = false
}

// setResponse sets the DNS response on dctx from the given upstream result.
func (s *Server) setResponse(dctx *dnsContext, resp *dns.Msg, u upstream.Upstream) {
	dctx.proxyCtx.Res = resp
	dctx.proxyCtx.Upstream = u
	dctx.responseFromUpstream = true
	dctx.responseAD = resp.AuthenticatedData
}

// resolveWithGroup routes resolution through the built-in proxy path, using
// only the given upstreams.  This ensures the proxy's caching, fallback, and
// stats mechanisms operate normally.
//
// CustomUpstreamConfig is set on the proxyCtx for the duration of this call
// and restored afterwards to avoid leaking state between requests.
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

	prevCustom := dctx.proxyCtx.CustomUpstreamConfig

	customUC := &proxy.UpstreamConfig{
		Upstreams: ups,
	}

	ednsEnabled := false
	if s.conf.EDNSClientSubnet != nil {
		ednsEnabled = s.conf.EDNSClientSubnet.Enabled
	}

	dctx.proxyCtx.CustomUpstreamConfig = proxy.NewCustomUpstreamConfig(
		customUC,
		s.conf.CacheEnabled,
		int(s.conf.CacheSize),
		ednsEnabled,
	)

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

// resolveNormally falls back to normal proxy resolution.
func (s *Server) resolveNormally(
	ctx context.Context,
	_ *slog.Logger,
	dctx *dnsContext,
) (rc resultCode) {
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

// exchangeWithUpstreams sends req to all ups in parallel and returns the first
// successful response.
func exchangeWithUpstreams(
	ups []upstream.Upstream,
	req *dns.Msg,
) (resp *dns.Msg, u upstream.Upstream, err error) {
	if len(ups) == 0 {
		return nil, nil, fmt.Errorf("no upstreams")
	}

	return upstream.ExchangeParallel(ups, req)
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
