package recursor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

func ecsQuery(name string, qtype uint16) *dns.Msg {
	q := query(name, qtype, false)
	opt := q.IsEdns0()
	opt.Option = append(opt.Option, dnsutils.NewEDNS0Subnet(net.ParseIP("198.51.100.0").To4(), 24, false))
	return q
}

func TestECSOnlyInFinalQuery(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, ecsQuery("cname.example.com.", dns.TypeA))
	for _, q := range e.net.queries() {
		final := (q.name == "cname.example.com." || q.name == "www.example.org.") && q.qtype == dns.TypeA
		if q.ecs != final {
			t.Fatalf("query %s %s to %s: ecs=%v", q.name, dns.TypeToString[q.qtype], q.addr, q.ecs)
		}
	}
	if e.net.count(func(q fakeQuery) bool { return q.ecs }) < 2 {
		t.Fatal("ecs was not sent along the cname chain")
	}
}

func TestECSFormErrFallback(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).formerrECS = true
	r := e.resolver()
	resp := resolve(t, r, ecsQuery("www.insecure.com.", dns.TypeA))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	ins := netip.MustParseAddr(addrInsecure)
	if !r.infra.noECS(ins) {
		t.Fatal("server not marked as not supporting ecs")
	}
	if e.net.count(func(q fakeQuery) bool { return q.addr == ins && q.edns && !q.ecs }) == 0 {
		t.Fatal("no retry without ecs")
	}
}

func TestECSScope(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).ecsScope = 24
	r := e.resolver()
	resp := resolve(t, r, ecsQuery("www.insecure.com.", dns.TypeA))
	ecs := dnsutils.GetMsgECS(resp)
	if ecs == nil || ecs.SourceScope != 24 || ecs.SourceNetmask != 24 {
		t.Fatalf("unexpected ecs in response: %v", ecs)
	}
	resolve(t, r, ecsQuery("www.insecure.com.", dns.TypeA))
	n := e.net.count(func(q fakeQuery) bool { return q.name == "www.insecure.com." })
	if n != 2 {
		t.Fatalf("answer with non-zero scope was cached internally: %d upstream queries", n)
	}
}

func TestECSScopeZeroCached(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, ecsQuery("www.insecure.com.", dns.TypeA))
	if ecs := dnsutils.GetMsgECS(resp); ecs == nil || ecs.SourceScope != 0 {
		t.Fatalf("unexpected ecs in response: %v", ecs)
	}
	resolve(t, r, ecsQuery("www.insecure.com.", dns.TypeA))
	resolve(t, r, query("www.insecure.com.", dns.TypeA, false))
	if n := e.net.count(func(q fakeQuery) bool { return q.name == "www.insecure.com." }); n != 1 {
		t.Fatalf("scope zero answer not reused: %d upstream queries", n)
	}
}
