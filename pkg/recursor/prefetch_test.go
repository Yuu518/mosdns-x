package recursor

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func prefetchIdle(r *Resolver) bool {
	idle := true
	r.prefetching.Range(func(any, any) bool {
		idle = false
		return false
	})
	return idle
}

func TestPrefetch(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver(func(o *Opts) { o.Prefetch = true })
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	e.clock.Advance(200 * time.Second)
	e.net.reset()
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if r.Stats().Prefetches != 0 {
		t.Fatal("prefetch started too early")
	}
	e.clock.Advance(80 * time.Second)
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	waitFor(t, "prefetch", func() bool { return r.Stats().Prefetches == 1 && prefetchIdle(r) })
	s := r.cache.getSet("www.example.com.", dns.TypeA, trustAnswer)
	if s == nil || r.cache.remaining(s.expire) < 250 {
		t.Fatal("entry was not refreshed in the background")
	}
}

func TestPrefetchDisabledByDefault(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	e.clock.Advance(290 * time.Second)
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if r.Stats().Prefetches != 0 {
		t.Fatal("prefetch ran without being enabled")
	}
}

func TestPrefetchKey(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver(func(o *Opts) { o.PrefetchKey = true })
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if !resp.AuthenticatedData {
		t.Fatalf("expected a secure answer, got %v", resp)
	}
	lame := netip.MustParseAddr(addrLame)
	n := e.net.count(func(q fakeQuery) bool {
		return q.name == "example.com." && q.qtype == dns.TypeDNSKEY && q.addr != lame
	})
	if n != 1 {
		t.Fatalf("dnskey fetched %d times", n)
	}
}
