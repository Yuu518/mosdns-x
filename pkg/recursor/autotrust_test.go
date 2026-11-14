package recursor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
)

func signKeys(now time.Time, keys []*dns.DNSKEY, signers ...*dnssectest.Key) []*dns.RRSIG {
	rrs := make([]dns.RR, len(keys))
	for i, k := range keys {
		rrs[i] = k
	}
	var sigs []*dns.RRSIG
	for _, s := range signers {
		sigs = append(sigs, s.Sign(rrs, now.Add(-time.Hour), now.Add(10*24*time.Hour)))
	}
	return sigs
}

func revoked(k *dnssectest.Key) *dnssectest.Key {
	c := *k.DNSKEY
	c.Flags |= dns.REVOKE
	return &dnssectest.Key{DNSKEY: &c, Signer: k.Signer}
}

func anchorTags(a *autoTrust) map[uint16]bool {
	out := make(map[uint16]bool)
	for _, ds := range a.anchors() {
		out[ds.KeyTag] = true
	}
	return out
}

func TestAutoTrustRollover(t *testing.T) {
	file := filepath.Join(t.TempDir(), "root.key")
	k1, k2, k3 := dnssectest.NewKey("."), dnssectest.NewKey("."), dnssectest.NewKey(".")
	a, err := newAutoTrust(file, []*dns.DS{k1.DS()}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	keys := []*dns.DNSKEY{k1.DNSKEY}
	a.update(keys, signKeys(now, keys, k1), now)
	if tags := anchorTags(a); len(tags) != 1 || !tags[k1.DNSKEY.KeyTag()] {
		t.Fatalf("bootstrap failed: %v", tags)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("state not saved: %v", err)
	}

	keys = []*dns.DNSKEY{k1.DNSKEY, k2.DNSKEY, k3.DNSKEY}
	a.update(keys, signKeys(now, keys, k1), now)
	if tags := anchorTags(a); len(tags) != 1 {
		t.Fatalf("new keys trusted before the hold-down: %v", tags)
	}

	now = now.Add(10 * 24 * time.Hour)
	keys = []*dns.DNSKEY{k1.DNSKEY, k2.DNSKEY}
	a.update(keys, signKeys(now, keys, k1), now)
	now = now.Add(21 * 24 * time.Hour)
	keys = []*dns.DNSKEY{k1.DNSKEY, k2.DNSKEY, k3.DNSKEY}
	a.update(keys, signKeys(now, keys, k1), now)
	tags := anchorTags(a)
	if len(tags) != 2 || !tags[k2.DNSKEY.KeyTag()] || tags[k3.DNSKEY.KeyTag()] {
		t.Fatalf("unexpected anchors after the hold-down: %v", tags)
	}

	r1 := revoked(k1)
	keys = []*dns.DNSKEY{r1.DNSKEY, k2.DNSKEY}
	a.update(keys, signKeys(now, keys, r1, k2), now)
	if tags := anchorTags(a); len(tags) != 1 || !tags[k2.DNSKEY.KeyTag()] {
		t.Fatalf("revoked key still trusted: %v", tags)
	}

	b, err := newAutoTrust(file, []*dns.DS{k1.DS()}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if tags := anchorTags(b); len(tags) != 1 || !tags[k2.DNSKEY.KeyTag()] {
		t.Fatalf("state not restored from file: %v", tags)
	}
}

func TestAutoTrustRevokeNeedsSelfSignature(t *testing.T) {
	file := filepath.Join(t.TempDir(), "root.key")
	k1, k2 := dnssectest.NewKey("."), dnssectest.NewKey(".")
	a, err := newAutoTrust(file, []*dns.DS{k1.DS(), k2.DS()}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	keys := []*dns.DNSKEY{k1.DNSKEY, k2.DNSKEY}
	a.update(keys, signKeys(now, keys, k1), now)
	keys = []*dns.DNSKEY{revoked(k1).DNSKEY, k2.DNSKEY}
	a.update(keys, signKeys(now, keys, k2), now)
	if tags := anchorTags(a); !tags[k1.DNSKEY.KeyTag()] {
		t.Fatal("revocation accepted without a self signature")
	}
}

func TestAutoTrustResolver(t *testing.T) {
	e := newTestEnv(t)
	file := filepath.Join(t.TempDir(), "root.key")
	r := e.resolver(func(o *Opts) { o.AutoTrustFile = file })
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if !resp.AuthenticatedData {
		t.Fatalf("expected a secure answer, got %v", resp)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "valid ") {
		t.Fatalf("unexpected state file %q", raw)
	}
	r2 := e.resolver(func(o *Opts) {
		o.AutoTrustFile = file
		o.TrustAnchors = []dns.RR{dnssectest.NewKey(".").DS()}
	})
	resp = resolve(t, r2, query("www.example.com.", dns.TypeA, true))
	if !resp.AuthenticatedData {
		t.Fatal("persisted trust anchors were not used")
	}
}
