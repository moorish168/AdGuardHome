package dnsforward

import (
	"github.com/AdguardTeam/dnsproxy/upstream"
)

// TrustedUpstream wraps an upstream.Upstream with a trust flag.  It implements
// the upstream.Upstream interface by embedding.
type TrustedUpstream struct {
	upstream.Upstream

	trusted bool
}

// NewTrustedUpstream wraps u with a trust flag.
func NewTrustedUpstream(u upstream.Upstream, trusted bool) (tu *TrustedUpstream) {
	return &TrustedUpstream{
		Upstream: u,
		trusted:  trusted,
	}
}

// IsTrusted returns true if this upstream is marked as trusted.
func (u *TrustedUpstream) IsTrusted() (trusted bool) {
	return u.trusted
}

// UpstreamTrusted reports whether u is a *TrustedUpstream with the trusted flag
// set.
func UpstreamTrusted(u upstream.Upstream) (trusted bool) {
	tu, ok := u.(*TrustedUpstream)

	return ok && tu.IsTrusted()
}
