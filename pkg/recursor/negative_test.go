package recursor

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func expectSecureNegative(t *testing.T, resp *dns.Msg, rcode int) {
	t.Helper()
	if resp.Rcode != rcode || len(resp.Answer) != 0 {
		t.Fatalf("expected %s without answers, got %v", dns.RcodeToString[rcode], resp)
	}
	if !resp.AuthenticatedData {
		t.Fatal("expected AD on a secure denial")
	}
	if !hasType(resp.Ns, dns.TypeSOA) || !hasType(resp.Ns, dns.TypeNSEC) {
		t.Fatalf("denial without soa or nsec: %v", resp.Ns)
	}
}

func TestAggressiveNSECNXDomain(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	expectSecureNegative(t, resolve(t, r, query("zz1.example.com.", dns.TypeA, true)), dns.RcodeNameError)
	e.net.reset()
	expectSecureNegative(t, resolve(t, r, query("zz2.example.com.", dns.TypeA, true)), dns.RcodeNameError)
	if n := len(e.net.queries()); n != 0 {
		t.Fatalf("covered name was queried upstream (%d queries)", n)
	}
	if r.Stats().Synthesized == 0 {
		t.Fatal("synthesized answers not counted")
	}
}

func TestAggressiveNSECNoData(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	expectSecureNegative(t, resolve(t, r, query("www.example.com.", dns.TypeTXT, true)), dns.RcodeSuccess)
	e.net.reset()
	expectSecureNegative(t, resolve(t, r, query("www.example.com.", dns.TypeMX, true)), dns.RcodeSuccess)
	if n := len(e.net.queries()); n != 0 {
		t.Fatalf("proven nodata was queried upstream (%d queries)", n)
	}
	resp := resolve(t, r, query("www.example.com.", dns.TypeAAAA, true))
	if len(answerOf(resp, dns.TypeAAAA)) != 1 {
		t.Fatalf("existing type denied: %v", resp)
	}
}

func TestAggressiveNSECNotForWildcardOrDelegation(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("zz1.example.com.", dns.TypeA, true))
	resolve(t, r, query("wild.example.com.", dns.TypeTXT, true))
	resp := resolve(t, r, query("foo.wild.example.com.", dns.TypeA, true))
	if as := answerOf(resp, dns.TypeA); len(as) != 1 || as[0].(*dns.A).A.String() != "192.0.2.9" {
		t.Fatalf("wildcard name denied from cached nsec: %v", resp)
	}
	resp = resolve(t, r, query("www.example.org.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("name in another zone denied: %v", resp)
	}
}

func TestNoSynthesisForInsecureZone(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("zz1.insecure.com.", dns.TypeA, true))
	e.net.reset()
	resp := resolve(t, r, query("zz2.insecure.com.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeNameError || resp.AuthenticatedData {
		t.Fatalf("unexpected response %v", resp)
	}
	if len(e.net.queries()) == 0 {
		t.Fatal("unsigned denial was used to synthesize an answer")
	}
}

func TestNoSynthesisWithoutValidation(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("zz1.example.com.", dns.TypeA, true))
	e.net.reset()
	q := query("zz2.example.com.", dns.TypeA, true)
	q.CheckingDisabled = true
	resolve(t, r, q)
	if len(e.net.queries()) == 0 {
		t.Fatal("checking disabled query was answered from validated proofs")
	}
}

func TestBelowNXDomain(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("zz1.example.com.", dns.TypeA, true))
	if r.belowNXDomain("a.b.zz1.example.com.", dns.TypeA) == nil {
		t.Fatal("secure nxdomain did not cover names below it")
	}
	e.net.reset()
	expectSecureNegative(t, resolve(t, r, query("a.b.zz1.example.com.", dns.TypeAAAA, true)), dns.RcodeNameError)
	if len(e.net.queries()) != 0 {
		t.Fatal("name below a known nxdomain was queried")
	}
	resolve(t, r, query("zz1.insecure.com.", dns.TypeA, true))
	if r.belowNXDomain("a.zz1.insecure.com.", dns.TypeA) != nil {
		t.Fatal("insecure nxdomain used for names below it")
	}
}

func TestMinimisedSecureNXDomainStops(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	expectSecureNegative(t, resolve(t, r, query("x.y.nx3.example.com.", dns.TypeA, true)), dns.RcodeNameError)
	for _, q := range e.net.queries() {
		if strings.HasPrefix(q.name, "x.") || strings.HasPrefix(q.name, "y.") {
			t.Fatalf("full name leaked after a secure nxdomain: %s", q.name)
		}
	}
}

func TestMinimisedInsecureNXDomainFallsBack(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("a.b.broken.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unsigned nxdomain for an empty non-terminal broke resolution: %v", resp)
	}
}
