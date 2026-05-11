package dnsforward

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDomainMatchesWildcard(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		patterns []string
		want     bool
	}{
		{name: "exact", host: "example.org", patterns: []string{"example.org"}, want: true},
		{name: "subdomain", host: "www.example.org", patterns: []string{"example.org"}, want: true},
		{name: "deep_subdomain", host: "a.b.example.org", patterns: []string{"example.org"}, want: true},
		{name: "different_domain", host: "other.com", patterns: []string{"example.org"}, want: false},
		{name: "no_false_suffix", host: "myexample.org", patterns: []string{"example.org"}, want: false},
		{name: "wildcard_subdomain", host: "www.example.org", patterns: []string{"*.example.org"}, want: true},
		{name: "wildcard_no_root", host: "example.org", patterns: []string{"*.example.org"}, want: false},
		{name: "wildcard_deep", host: "a.b.example.org", patterns: []string{"*.example.org"}, want: true},
		{name: "multiple_patterns", host: "www.example.org", patterns: []string{"other.com", "example.org"}, want: true},
		{name: "case_insensitive_upper_host", host: "WWW.EXAMPLE.ORG", patterns: []string{"example.org"}, want: true},
		{name: "case_insensitive_upper_pattern", host: "www.example.org", patterns: []string{"EXAMPLE.ORG"}, want: true},
		{name: "empty_patterns", host: "example.org", patterns: nil, want: false},
		{name: "comment_pattern", host: "example.org", patterns: []string{"# comment", "example.org"}, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := domainMatchesWildcard(tc.host, tc.patterns)
			assert.Equal(t, tc.want, got, "host=%q patterns=%v", tc.host, tc.patterns)
		})
	}
}

func TestIPMatchesAny(t *testing.T) {
	tests := []struct {
		name     string
		addrs    []netip.Addr
		patterns []string
		want     bool
	}{
		{
			name:     "exact_ip_match",
			addrs:    []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			patterns: []string{"192.168.1.1"},
			want:     true,
		},
		{
			name:     "exact_ip_no_match",
			addrs:    []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			patterns: []string{"10.0.0.1"},
			want:     false,
		},
		{
			name:     "cidr_match",
			addrs:    []netip.Addr{netip.MustParseAddr("192.168.1.100")},
			patterns: []string{"192.168.1.0/24"},
			want:     true,
		},
		{
			name:     "cidr_no_match",
			addrs:    []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			patterns: []string{"192.168.1.0/24"},
			want:     false,
		},
		{
			name:     "multiple_addrs_one_match",
			addrs:    []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.1.1")},
			patterns: []string{"192.168.1.1"},
			want:     true,
		},
		{
			name:     "empty_addrs",
			addrs:    nil,
			patterns: []string{"192.168.1.1"},
			want:     false,
		},
		{
			name:     "empty_patterns",
			addrs:    []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			patterns: nil,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ipMatchesAny(tc.addrs, tc.patterns)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractIPsFromMsg(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{A: netip.MustParseAddr("192.168.1.1").AsSlice()},
		&dns.AAAA{AAAA: netip.MustParseAddr("::1").AsSlice()},
		&dns.CNAME{Target: "example.org."},
	}

	ips := extractIPsFromMsg(msg)
	assert.Len(t, ips, 2)
	assert.Contains(t, ips, netip.MustParseAddr("192.168.1.1"))
	assert.Contains(t, ips, netip.MustParseAddr("::1"))
}

func TestExtractIPsFromMsg_Nil(t *testing.T) {
	ips := extractIPsFromMsg(nil)
	assert.Nil(t, ips)
}

func TestSplitUpstreamsByTrust(t *testing.T) {
	var ups []upstream.Upstream
	ups = append(ups, NewTrustedUpstream(nil, true))
	ups = append(ups, NewTrustedUpstream(nil, false))
	ups = append(ups, nil)

	trusted, untrusted := splitUpstreamsByTrust(ups)
	assert.Len(t, trusted, 1)
	assert.Len(t, untrusted, 2)
}

func TestUpstreamTrusted(t *testing.T) {
	assert.True(t, UpstreamTrusted(NewTrustedUpstream(nil, true)))
	assert.False(t, UpstreamTrusted(NewTrustedUpstream(nil, false)))
	assert.False(t, UpstreamTrusted(nil))
}
