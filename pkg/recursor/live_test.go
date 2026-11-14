package recursor

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func liveResolver(t *testing.T, mod ...func(o *Opts)) *Resolver {
	t.Helper()
	if os.Getenv("MOSDNS_TEST_LIVE") != "1" {
		t.Skip("set MOSDNS_TEST_LIVE=1 to run tests against the real dns")
	}
	o := Opts{}
	if os.Getenv("MOSDNS_TEST_LIVE_IPV6") != "1" {
		o.NoIPv6 = true
	}
	for _, f := range mod {
		f(&o)
	}
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func liveResolve(t *testing.T, r *Resolver, name string, qtype uint16) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := r.Resolve(ctx, query(name, qtype, true))
	if err != nil {
		t.Fatalf("%s %s: %v", name, dns.TypeToString[qtype], err)
	}
	t.Logf("%s %s: %s ad=%v answers=%d in %s", name, dns.TypeToString[qtype], dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, len(resp.Answer), time.Since(start))
	return resp
}

func TestLive(t *testing.T) {
	r := liveResolver(t)

	resp := liveResolve(t, r, "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(answerOf(resp, dns.TypeA)) == 0 || !resp.AuthenticatedData {
		t.Fatalf("example.com: %v", resp)
	}
	start := time.Now()
	liveResolve(t, r, "example.com.", dns.TypeA)
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("second query was not served from cache")
	}

	resp = liveResolve(t, r, "baidu.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(answerOf(resp, dns.TypeA)) == 0 || resp.AuthenticatedData {
		t.Fatalf("baidu.com: %v", resp)
	}

	resp = liveResolve(t, r, "dnssec-failed.org.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("dnssec-failed.org: %v", resp)
	}
	if ede, ok := edeOf(resp); ok {
		t.Logf("dnssec-failed.org ede: %d %s", ede, dns.ExtendedErrorCodeToString[ede])
	}

	resp = liveResolve(t, r, "this-name-does-not-exist-mosdns-x.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("nonexistent name: %v", resp)
	}

	resp = liveResolve(t, r, "nonexistent.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError || !resp.AuthenticatedData {
		t.Fatalf("nonexistent name in a signed zone: %v", resp)
	}

	t.Logf("stats: %+v", r.Stats())
}

func TestLiveLocalRoot(t *testing.T) {
	r := liveResolver(t, func(o *Opts) { o.LocalRoot = true })
	deadline := time.Now().Add(2 * time.Minute)
	for !r.local.active() {
		if time.Now().After(deadline) {
			t.Fatal("local root zone did not load")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("local root serial %d", r.local.serial())
	before := r.Stats().UpstreamQueries
	resp := liveResolve(t, r, "www.nonexistent-tld-mosdns-x.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError || !resp.AuthenticatedData {
		t.Fatalf("nonexistent tld: %v", resp)
	}
	if after := r.Stats().UpstreamQueries; after != before {
		t.Fatalf("nonexistent tld caused %d upstream queries", after-before)
	}
	resp = liveResolve(t, r, "example.com.", dns.TypeA)
	if !resp.AuthenticatedData {
		t.Fatalf("example.com: %v", resp)
	}
}

func TestLiveOpportunisticDoT(t *testing.T) {
	r := liveResolver(t, func(o *Opts) { o.OpportunisticDoT = true })
	liveResolve(t, r, "facebook.com.", dns.TypeA)
	ns := r.cache.getSet("facebook.com.", dns.TypeNS, trustAuthority)
	if ns == nil {
		t.Fatal("facebook.com ns not cached")
	}
	var addrs []netip.Addr
	cached, _ := r.cachedAddrs("facebook.com.", ns, false)
	addrs = append(addrs, cached...)
	deadline := time.Now().Add(10 * time.Second)
	ok := false
	for !ok && time.Now().Before(deadline) {
		for _, a := range addrs {
			if r.infra.dotStatus(a) == dotOK {
				ok = true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ok {
		t.Skip("no facebook.com name server accepted dot from this network")
	}
	r.cache.delSet("facebook.com.", dns.TypeAAAA)
	liveResolve(t, r, "facebook.com.", dns.TypeAAAA)
	if r.Stats().DoTQueries == 0 {
		t.Fatal("dot was not used after a successful probe")
	}
	t.Logf("stats: %+v", r.Stats())
}
