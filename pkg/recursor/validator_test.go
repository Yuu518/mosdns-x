package recursor

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
)

func expectBogus(t *testing.T, resp *dns.Msg, ede uint16) {
	t.Helper()
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected servfail, got %s", dns.RcodeToString[resp.Rcode])
	}
	got, ok := edeOf(resp)
	if !ok || got != ede {
		t.Fatalf("expected ede %d, got %d (present=%v)", ede, got, ok)
	}
	if resp.AuthenticatedData {
		t.Fatal("AD set on a bogus answer")
	}
}

func TestInsecureDelegation(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.insecure.com.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeSuccess || len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	if resp.AuthenticatedData {
		t.Fatal("AD set for an insecure zone")
	}
	if s := r.Stats(); s.Insecure != 1 || s.Bogus != 0 {
		t.Fatalf("unexpected stats %+v", s)
	}
}

func TestBogusTampered(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).tamper = true
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	expectBogus(t, resp, dns.ExtendedErrorCodeDNSBogus)

	e.net.reset()
	resp = resolve(t, r, query("www.example.com.", dns.TypeA, true))
	expectBogus(t, resp, dns.ExtendedErrorCodeDNSBogus)
	if len(e.net.queries()) != 0 {
		t.Fatal("bogus result was not cached")
	}

	q := query("www.example.com.", dns.TypeA, true)
	q.CheckingDisabled = true
	resp = resolve(t, r, q)
	if resp.Rcode != dns.RcodeSuccess || len(answerOf(resp, dns.TypeA)) != 1 || resp.AuthenticatedData {
		t.Fatalf("cd query should return the unvalidated answer, got %v", resp)
	}
	if s := r.Stats(); s.Bogus != 2 {
		t.Fatalf("unexpected stats %+v", s)
	}
}

func TestBogusRetriesAnotherServer(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).tamper = true
	lame := e.net.server(addrLame)
	lame.refuse = false
	lame.zones = e.net.server(addrExampleCom).zones
	for i := 0; i < 5; i++ {
		r := e.resolver()
		resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
		if resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
			t.Fatalf("expected a secure answer from the good server, got %v", resp)
		}
	}
}

func TestMissingSignatures(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).stripSigs = true
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	expectBogus(t, resp, dns.ExtendedErrorCodeRRSIGsMissing)
}

func TestDNSSECLameServerSkipped(t *testing.T) {
	e := newTestEnv(t)
	lame := e.net.server(addrLame)
	lame.refuse = false
	lame.zones = e.net.server(addrExampleCom).zones
	lame.stripSigs = true
	for i := 0; i < 6; i++ {
		r := e.resolver()
		resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
		if resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
			t.Fatalf("answer without signatures was not retried elsewhere: %v", resp)
		}
	}
}

func TestSignatureExpiryCapsTTL(t *testing.T) {
	e := newTestEnv(t)
	z := e.zones["example.com."]
	z.Expiration = e.clock.Now().Add(100 * time.Second)
	z.Resign()
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	as := answerOf(resp, dns.TypeA)
	if len(as) != 1 || !resp.AuthenticatedData {
		t.Fatalf("unexpected response %v", resp)
	}
	if ttl := as[0].Header().Ttl; ttl > 100 {
		t.Fatalf("ttl %d outlives the signature", ttl)
	}
	e.clock.Advance(101 * time.Second)
	if r.cache.getSet("www.example.com.", dns.TypeA, trustAnswer) != nil {
		t.Fatal("secure entry cached past its signature expiration")
	}
}

func TestDSMismatch(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.badds.com.", dns.TypeA, true))
	expectBogus(t, resp, dns.ExtendedErrorCodeDNSKEYMissing)
}

func TestExpiredSignatures(t *testing.T) {
	e := newTestEnv(t)
	e.clock.Advance(60 * 24 * time.Hour)
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	expectBogus(t, resp, dns.ExtendedErrorCodeSignatureExpired)
}

func TestUnsupportedAlgorithmIsInsecure(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.unsup.com.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeSuccess || len(answerOf(resp, dns.TypeA)) != 1 || resp.AuthenticatedData {
		t.Fatalf("expected an insecure answer, got %v", resp)
	}
}

func TestNoDOStripsDNSSECRecords(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if hasType(resp.Answer, dns.TypeRRSIG) || resp.AuthenticatedData {
		t.Fatalf("dnssec records leaked without DO: %v", resp)
	}
	resp = resolve(t, r, query("nope.example.com.", dns.TypeA, false))
	if hasType(resp.Ns, dns.TypeNSEC) || hasType(resp.Ns, dns.TypeRRSIG) || !hasType(resp.Ns, dns.TypeSOA) {
		t.Fatalf("unexpected authority without DO: %v", resp.Ns)
	}
	q := query("www.example.com.", dns.TypeA, false)
	q.AuthenticatedData = true
	resp = resolve(t, r, q)
	if !resp.AuthenticatedData || hasType(resp.Answer, dns.TypeRRSIG) {
		t.Fatalf("expected AD without signatures when the query sets AD, got %v", resp)
	}
}

func TestDNSKEYFetchedOnce(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, true))
	resolve(t, r, query("other.example.com.", dns.TypeA, true))
	resolve(t, r, query("www.example.com.", dns.TypeAAAA, true))
	lame := netip.MustParseAddr(addrLame)
	n := e.net.count(func(q fakeQuery) bool {
		return q.name == "example.com." && q.qtype == dns.TypeDNSKEY && q.addr != lame
	})
	if n != 1 {
		t.Fatalf("dnskey fetched %d times", n)
	}
}

func TestValidationDisabled(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).tamper = true
	r := e.resolver(func(o *Opts) { o.DisableDNSSEC = true })
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeSuccess || resp.AuthenticatedData {
		t.Fatalf("unexpected response %v", resp)
	}
	if e.net.count(func(q fakeQuery) bool { return q.qtype == dns.TypeDNSKEY }) != 0 {
		t.Fatal("dnskey fetched with validation disabled")
	}
}

func TestNonDNSSECAwareParent(t *testing.T) {
	const addrPlain, addrSub = "10.0.9.1", "10.0.9.2"
	e := newTestEnv(t)
	com := e.zones["com."]
	com.AddText("plain.com. 172800 NS ns.plain.com.\nns.plain.com. 172800 A " + addrPlain + "\n")
	com.Resign()
	plain := dnssectest.NewZone("plain.com.", zoneText(
		"plain.com. 3600 SOA ns.plain.com. admin.plain.com. 1 3600 600 86400 300",
		"plain.com. 3600 NS ns.plain.com.",
		"ns.plain.com. 3600 A "+addrPlain,
		"sub.plain.com. 3600 NS ns.sub.plain.com.",
		"ns.sub.plain.com. 3600 A "+addrSub,
	))
	sub := dnssectest.NewZone("sub.plain.com.", zoneText(
		"sub.plain.com. 3600 SOA ns.sub.plain.com. admin.plain.com. 1 3600 600 86400 300",
		"sub.plain.com. 3600 NS ns.sub.plain.com.",
		"ns.sub.plain.com. 3600 A "+addrSub,
		"www.sub.plain.com. 300 A 192.0.2.80",
	))
	e.net.add(addrPlain, &fakeServer{handler: func(q *dns.Msg) *dns.Msg {
		if q.Question[0].Qtype != dns.TypeDS {
			return plain.Answer(q)
		}
		c := q.Copy()
		c.Question[0].Qtype = dns.TypeA
		r := plain.Answer(c)
		r.Question = q.Question
		return r
	}})
	e.net.add(addrSub, &fakeServer{zones: []*dnssectest.Zone{sub}})
	r := e.resolver()

	resp := resolve(t, r, query("www.sub.plain.com.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeSuccess || len(answerOf(resp, dns.TypeA)) != 1 || resp.AuthenticatedData {
		t.Fatalf("expected an insecure answer, got %v", resp)
	}
	plainAddr := netip.MustParseAddr(addrPlain)
	if n := e.net.count(func(q fakeQuery) bool { return q.addr == plainAddr && q.qtype == dns.TypeDS }); n != 0 {
		t.Fatalf("sent %d ds queries into an insecure zone", n)
	}

	resp = resolve(t, r, query("sub.plain.com.", dns.TypeDS, true))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("a referral in reply to a ds query should mean no ds, got %v", resp)
	}
}

func TestValidatedFromCache(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, true))
	e.net.reset()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if !resp.AuthenticatedData {
		t.Fatal("cached secure answer lost AD")
	}
	if len(e.net.queries()) != 0 {
		t.Fatal("cached answer caused network queries")
	}
}
