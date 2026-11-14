package recursor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
)

func TestBasicResolution(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	as := answerOf(resp, dns.TypeA)
	if len(as) != 1 || as[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("unexpected answer %v", resp.Answer)
	}
	if !resp.RecursionAvailable || resp.Authoritative {
		t.Fatalf("bad flags: ra=%v aa=%v", resp.RecursionAvailable, resp.Authoritative)
	}
	if !resp.AuthenticatedData {
		t.Fatal("expected AD for a fully signed chain")
	}
	if !hasType(resp.Answer, dns.TypeRRSIG) {
		t.Fatal("expected RRSIG with DO")
	}
}

func TestQueryNotModified(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	q := query("WWW.Example.COM.", dns.TypeA, true)
	q.Id = 4242
	before := q.String()
	resp := resolve(t, r, q)
	if q.String() != before {
		t.Fatal("query was modified")
	}
	if resp.Id != 4242 || resp.Question[0].Name != "WWW.Example.COM." {
		t.Fatalf("response does not mirror the query: %v", resp.Question)
	}
}

func TestNoGlue(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.noglue.com.", dns.TypeA, true))
	as := answerOf(resp, dns.TypeA)
	if len(as) != 1 || as[0].(*dns.A).A.String() != "192.0.2.40" {
		t.Fatalf("unexpected answer %v", resp)
	}
}

func TestMutualNSLoop(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := r.Resolve(ctx, query("www.loopa.com.", dns.TypeA, true))
	if err == nil {
		t.Fatal("expected failure for mutually dependent delegations")
	}
	if ctx.Err() != nil || time.Since(start) > 3*time.Second {
		t.Fatalf("loop did not terminate promptly: %v", err)
	}
}

func TestCNAMEChain(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("cname.example.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeCNAME)) != 1 || len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected answer %v", resp.Answer)
	}
	if !resp.AuthenticatedData {
		t.Fatal("expected AD for a signed cross-zone chain")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, query("loop1.example.com.", dns.TypeA, true)); !errors.Is(err, errCNAMEChain) {
		t.Fatalf("expected cname loop error, got %v", err)
	}
}

func TestDNAME(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.dn.example.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeDNAME)) != 1 || len(answerOf(resp, dns.TypeCNAME)) != 1 {
		t.Fatalf("expected dname and synthesized cname, got %v", resp.Answer)
	}
	as := answerOf(resp, dns.TypeA)
	if len(as) != 1 || as[0].(*dns.A).A.String() != "192.0.2.20" {
		t.Fatalf("unexpected answer %v", resp.Answer)
	}
	if !resp.AuthenticatedData {
		t.Fatal("expected AD through a signed dname")
	}
}

func TestNXDomainAndNoData(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("nope.example.com.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeNameError || !hasType(resp.Ns, dns.TypeSOA) {
		t.Fatalf("expected nxdomain with soa, got %v", resp)
	}
	if !resp.AuthenticatedData {
		t.Fatal("expected AD for a proven nxdomain")
	}

	resp = resolve(t, r, query("www.example.com.", dns.TypeMX, true))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || !hasType(resp.Ns, dns.TypeSOA) {
		t.Fatalf("expected nodata, got %v", resp)
	}
	if !resp.AuthenticatedData {
		t.Fatal("expected AD for a proven nodata")
	}

	resp = resolve(t, r, query("nope.example.org.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeNameError || !resp.AuthenticatedData {
		t.Fatalf("expected secure nxdomain via nsec3, got %v", resp)
	}

	resp = resolve(t, r, query("x.wild.example.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeA)) != 1 || !resp.AuthenticatedData {
		t.Fatalf("expected secure wildcard answer, got %v", resp)
	}
}

func TestLameServerSkipped(t *testing.T) {
	e := newTestEnv(t)
	for i := 0; i < 5; i++ {
		r := e.resolver()
		resp := resolve(t, r, query("other.example.com.", dns.TypeA, false))
		if len(answerOf(resp, dns.TypeA)) != 1 {
			t.Fatalf("unexpected answer %v", resp)
		}
	}
}

func TestTruncatedRetriesTCP(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).truncate = true
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeA)) != 1 || !resp.AuthenticatedData {
		t.Fatalf("unexpected answer %v", resp)
	}
	if e.net.count(func(q fakeQuery) bool { return q.proto == protoTCP }) == 0 {
		t.Fatal("no tcp retry was made")
	}
}

func TestEDNSFallback(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).formerrEDNS = true
	r := e.resolver()
	resp := resolve(t, r, query("www.insecure.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected answer %v", resp)
	}
	ins := netip.MustParseAddr(addrInsecure)
	if e.net.count(func(q fakeQuery) bool { return q.addr == ins && !q.edns }) == 0 {
		t.Fatal("no query without edns was sent")
	}
	if !r.infra.noEDNS(ins, "insecure.com.") {
		t.Fatal("server was not marked as not supporting edns")
	}
	if r.infra.noEDNS(ins, "com.") {
		t.Fatal("edns state leaked to another zone")
	}
	e.clock.Advance(ednsDuration + time.Second)
	if r.infra.noEDNS(ins, "insecure.com.") {
		t.Fatal("edns state did not expire")
	}
}

func TestEDNSFallbackNotStoredForSignedZone(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).formerrEDNS = true
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if r.infra.noEDNS(netip.MustParseAddr(addrExampleCom), "example.com.") {
		t.Fatal("edns disabled for a server of a signed zone")
	}
}

func TestEDNSKnownWorkingNotDowngraded(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("www.insecure.com.", dns.TypeA, false))
	e.net.server(addrInsecure).formerrEDNS = true
	r.cache.delSet("www.insecure.com.", dns.TypeAAAA)
	resolve(t, r, query("www.insecure.com.", dns.TypeAAAA, false))
	if r.infra.noEDNS(netip.MustParseAddr(addrInsecure), "insecure.com.") {
		t.Fatal("a single formerr downgraded a server known to support edns")
	}
}

func TestOutOfBailiwickNotCached(t *testing.T) {
	e := newTestEnv(t)
	evil, _ := dns.NewRR("www.victim.org. 3600 IN A 6.6.6.6")
	e.net.server(addrCom).inject = []dns.RR{evil}
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	for _, tr := range []trustLevel{trustGlue, trustAuthority, trustAnswer} {
		if s := r.cache.getSet("www.victim.org.", dns.TypeA, tr); s != nil {
			t.Fatal("out of bailiwick record was cached")
		}
	}
}

func TestUpwardReferralRejected(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).handler = func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		ns, _ := dns.NewRR("com. 3600 IN NS ns.com.")
		m.Ns = []dns.RR{ns}
		return m
	}
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, query("www.insecure.com.", dns.TypeA, false)); err == nil {
		t.Fatal("expected failure for an upward referral")
	}
	if e.net.count(func(q fakeQuery) bool { return q.addr == netip.MustParseAddr(addrCom) && q.name == "www.insecure.com." }) != 0 {
		t.Fatal("upward referral was followed")
	}
}

func TestNonAuthoritativeServer(t *testing.T) {
	e := newTestEnv(t)
	z := e.zones["insecure.com."]
	z.AddText("deep.x.insecure.com. 300 A 192.0.2.31\n")
	e.net.server(addrInsecure).handler = func(q *dns.Msg) *dns.Msg {
		r := z.Answer(q)
		r.Authoritative = false
		if len(r.Answer) == 0 && r.Rcode == dns.RcodeSuccess {
			r.Ns = nil
		}
		return r
	}
	r := e.resolver()
	resp := resolve(t, r, query("www.insecure.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("answer without AA rejected: %v", resp)
	}
	resp = resolve(t, r, query("deep.x.insecure.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("empty non-authoritative reply for an empty non-terminal broke resolution: %v", resp)
	}
	resp = resolve(t, r, query("www.insecure.com.", dns.TypeAAAA, false))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("expected nodata, got %v", resp)
	}
	resp = resolve(t, r, query("nope.insecure.com.", dns.TypeA, false))
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected nxdomain, got %v", resp)
	}
	if e.net.count(func(q fakeQuery) bool { return q.name == "x.insecure.com." }) == 0 {
		t.Fatal("minimized query not sent")
	}
}

func TestRecursiveLameServer(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).handler = func(q *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.SetReply(q)
		r.RecursionAvailable = true
		return r
	}
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := r.Resolve(ctx, query("www.insecure.com.", dns.TypeA, false))
	if err == nil {
		t.Fatal("empty recursive reply accepted as nodata")
	}
	t.Log(err)
}

func TestRefetchDelegationWhenGlueMissing(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if r.cache.getSet("example.com.", dns.TypeNS, trustAuthority) == nil {
		t.Fatal("delegation not cached")
	}
	for _, h := range []string{"ns1.example.com.", "lame.example.com."} {
		r.cache.delSet(h, dns.TypeA)
		r.cache.parent.Del(setKey(h, dns.TypeA))
	}
	r.cache.parent.Del(setKey("example.com.", dns.TypeNS))
	e.net.reset()
	resp := resolve(t, r, query("other.example.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	if e.net.countTo(addrCom) == 0 {
		t.Fatal("delegation was not refetched from the parent")
	}
}

func TestParentSideGlueFallback(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	child := mustParseRRs("example.com. 3600 NS ns9.example.com.\n")
	ns := &rrset{name: "example.com.", rtype: dns.TypeNS, rrs: child}
	r.finishSet(ns, "example.com.", netip.Addr{}, trustAnswer, maxCacheTTL)
	r.cache.putSet(ns)
	for _, h := range []string{"ns1.example.com.", "lame.example.com."} {
		r.cache.delSet(h, dns.TypeA)
	}
	e.net.reset()
	resp := resolve(t, r, query("other.example.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	if e.net.countTo(addrCom) != 0 {
		t.Fatal("parent-side glue was not used")
	}
	if r.cache.getSet("example.com.", dns.TypeNS, trustAuthority) == nil {
		t.Fatal("child-side ns set was dropped")
	}
}

func TestNSAddressExpiredWhileOtherTypeNegative(t *testing.T) {
	e := newTestEnv(t)
	org := e.zones["example.org."]
	org.Remove("ns.example.org.", dns.TypeA)
	org.AddText("ns.example.org. 60 A " + addrExampleOrg + "\n")
	org.Resign()
	e.zones["noglue.com."].AddText("mail.noglue.com. 300 A 192.0.2.41\n")
	r := e.resolver(func(o *Opts) { o.NoIPv6 = false })
	resolve(t, r, query("www.noglue.com.", dns.TypeA, false))
	if r.cache.getNeg("ns.example.org.", dns.TypeAAAA) == nil {
		t.Fatal("aaaa of the name server host was not negatively cached")
	}
	r.cache.parent.Del(setKey("ns.example.org.", dns.TypeA))
	e.clock.Advance(120 * time.Second)
	if r.cache.getSet("ns.example.org.", dns.TypeA, trustGlue) != nil {
		t.Fatal("a record of the name server host did not expire")
	}
	resp := resolve(t, r, query("mail.noglue.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
}

func TestShortLivedNSHostWithoutGlue(t *testing.T) {
	e := newTestEnv(t)
	const addrTdns, addrVod = "10.0.9.1", "10.0.9.2"
	com := e.zones["com."]
	com.AddText("tdns.com. 172800 NS ns1.tdns.com.\nns1.tdns.com. 172800 A " + addrTdns + "\n")
	com.Resign()
	tdns := dnssectest.NewZone("tdns.com.", zoneText(
		"tdns.com. 7200 SOA ns1.tdns.com. webmaster.tdns.com. 1 300 600 86400 300",
		"ns1.tdns.com. 180 A "+addrTdns,
		"ns1.vod1.tdns.com. 180 A "+addrVod,
		"vodty.tdns.com. 60 NS ns1.vod1.tdns.com.",
	))
	vodty := dnssectest.NewZone("vodty.tdns.com.", zoneText(
		"vodty.tdns.com. 60 SOA ns1.vod1.tdns.com. webmaster.vodty.tdns.com. 1 300 600 86400 300",
		"vodty.tdns.com. 60 NS ns1.vod1.tdns.com.",
		"ty.sched.vodty.tdns.com. 38 A 192.0.2.80",
	))
	e.net.add(addrTdns, &fakeServer{handler: func(q *dns.Msg) *dns.Msg {
		m := tdns.Answer(q)
		if dns.CanonicalName(q.Question[0].Name) == "vod1.tdns.com." {
			m.Rcode = dns.RcodeNameError
		}
		m.Extra = stripType(m.Extra, dns.TypeA)
		return m
	}})
	e.net.add(addrVod, &fakeServer{zones: []*dnssectest.Zone{vodty}})
	r := e.resolver(func(o *Opts) { o.NoIPv6 = false })
	for i := 0; i < 24; i++ {
		resp := resolve(t, r, query("ty.sched.vodty.tdns.com.", dns.TypeA, false))
		if len(answerOf(resp, dns.TypeA)) != 1 {
			t.Fatalf("round %d: unexpected response %v", i, resp)
		}
		resolve(t, r, query("ty.sched.vodty.tdns.com.", dns.TypeAAAA, false))
		e.clock.Advance(40 * time.Second)
	}
}

func resolveErr(r *Resolver, q *dns.Msg) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := r.Resolve(ctx, q)
	return err
}

func TestOutOfZoneDNAMEIgnored(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).handler = func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		d, _ := dns.NewRR("com. 300 IN DNAME x.")
		m.Answer = []dns.RR{d}
		return m
	}
	r := e.resolver()
	err := resolveErr(r, query("www.insecure.com.", dns.TypeA, false))
	if err == nil || errors.Is(err, errInternal) {
		t.Fatalf("out-of-zone dname not rejected cleanly: %v", err)
	}
}

func TestNonINReferralIgnored(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).handler = func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		ns, _ := dns.NewRR("www.insecure.com. 300 CH NS ns.example.org.")
		m.Ns = []dns.RR{ns}
		return m
	}
	r := e.resolver()
	if err := resolveErr(r, query("www.insecure.com.", dns.TypeA, false)); errors.Is(err, errInternal) {
		t.Fatalf("non-in referral caused an internal error: %v", err)
	}
}

func TestPanicDoesNotCrash(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).handler = func(q *dns.Msg) *dns.Msg {
		panic("boom")
	}
	r := e.resolver()
	if err := resolveErr(r, query("www.insecure.com.", dns.TypeA, false)); !errors.Is(err, errInternal) {
		t.Fatalf("expected an internal error, got %v", err)
	}
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if !resp.AuthenticatedData {
		t.Fatal("resolver unusable after a recovered panic")
	}
}

func TestQueryBudget(t *testing.T) {
	e := newTestEnv(t)
	z := e.zones["com."]
	for i := 0; i < 150; i++ {
		z.AddText(fmt.Sprintf("many.com. 172800 NS ns%d.dead%d.com.\ndead%d.com. 172800 NS ns.dead%d.com.\nns.dead%d.com. 172800 A %s\n", i, i, i, i, i, addrLame))
	}
	z.Resign()
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, query("www.many.com.", dns.TypeA, false)); err == nil {
		t.Fatal("expected failure")
	}
	n := e.net.count(func(q fakeQuery) bool { return !(q.name == "." && q.qtype == dns.TypeNS) })
	if n > 4*maxDPTargets {
		t.Fatalf("sent %d queries for a delegation with unusable name servers", n)
	}
}

func TestNXNSLimit(t *testing.T) {
	e := newTestEnv(t)
	z := e.zones["com."]
	for i := 0; i < 100; i++ {
		z.AddText(fmt.Sprintf("victim.com. 172800 NS nx%d.example.com.\n", i))
	}
	z.Resign()
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, query("www.victim.com.", dns.TypeA, false)); err == nil {
		t.Fatal("expected failure")
	}
	n := e.net.count(func(q fakeQuery) bool {
		return q.addr == netip.MustParseAddr(addrExampleCom) && len(q.name) > 2 && q.name[:2] == "nx"
	})
	if n == 0 || n > maxTargetNXParent+3 {
		t.Fatalf("sent %d queries for nonexistent name server names", n)
	}
}

func TestEmptyNoDataRetried(t *testing.T) {
	e := newTestEnv(t)
	lame := e.net.server(addrLame)
	lame.refuse = false
	lame.handler = func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		return m
	}
	for i := 0; i < 6; i++ {
		r := e.resolver()
		resp := resolve(t, r, query("www.example.com.", dns.TypeA, false))
		if len(answerOf(resp, dns.TypeA)) != 1 {
			t.Fatalf("empty reply was accepted as nodata: %v", resp)
		}
	}
}

func TestLoopbackNotQueried(t *testing.T) {
	e := newTestEnv(t)
	z := e.zones["com."]
	z.AddText("evil.com. 172800 NS ns.evil.com.\nns.evil.com. 172800 A 127.0.0.1\n")
	z.Resign()
	e.net.add("127.0.0.1", &fakeServer{zones: []*dnssectest.Zone{e.zones["insecure.com."]}})
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, query("www.evil.com.", dns.TypeA, false)); err == nil {
		t.Fatal("expected failure")
	}
	if e.net.countTo("127.0.0.1") != 0 {
		t.Fatal("a loopback name server address was queried")
	}
}

func TestRecursiveNXDomainIsLame(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrInsecure).handler = func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeNameError)
		m.RecursionAvailable = true
		soa, _ := dns.NewRR("insecure.com. 300 IN SOA ns.insecure.com. admin.insecure.com. 1 3600 600 86400 300")
		m.Ns = []dns.RR{soa}
		return m
	}
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Resolve(ctx, query("www.insecure.com.", dns.TypeA, false)); err == nil {
		t.Fatal("nxdomain from a recursive server was accepted")
	}
}

func TestMinimizedName(t *testing.T) {
	name := "l1.l2.l3.l4.l5.l6.l7.l8.l9.l10.l11.l12.l13.l14.example."
	known := "example."
	var steps []string
	for i := 0; ; i++ {
		m, ok := minimizedName(name, known, i)
		if !ok {
			break
		}
		if dns.CountLabel(m) <= dns.CountLabel(known) || !dns.IsSubDomain(m, name) {
			t.Fatalf("bad step %q after %q", m, known)
		}
		steps = append(steps, m)
		known = m
	}
	if len(steps) >= maxMinimizeSteps {
		t.Fatalf("too many minimised steps: %v", steps)
	}
	for i := 0; i < minimiseOneLab; i++ {
		if dns.CountLabel(steps[i]) != i+2 {
			t.Fatalf("first steps must add one label: %v", steps)
		}
	}
	if dns.CountLabel(steps[len(steps)-1]) < dns.CountLabel(name)-2 {
		t.Fatalf("minimisation stopped too early: %v", steps)
	}
	if m, ok := minimizedName("a.b.example.com.", "example.com.", 0); !ok || m != "b.example.com." {
		t.Fatalf("unexpected short name step %q", m)
	}
	if _, ok := minimizedName("b.example.com.", "example.com.", 0); ok {
		t.Fatal("a name one label below the cut must not be minimised")
	}
}

func TestInfraRTO(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	in := newInfra(clock.Now)
	a := netip.MustParseAddr("192.0.2.1")
	if in.timeout(a) != unknownTimeout {
		t.Fatal("unexpected timeout for an unknown server")
	}
	for i := 0; i < 20; i++ {
		in.success(a, 50*time.Millisecond)
	}
	if got := in.timeout(a); got != minTimeout {
		t.Fatalf("stable fast server timeout %v", got)
	}
	in.failure(a, minTimeout)
	if got := in.timeout(a); got != 2*minTimeout {
		t.Fatalf("timeout not doubled after a loss: %v", got)
	}
	in.success(a, 50*time.Millisecond)
	if got := in.timeout(a); got != minTimeout {
		t.Fatalf("timeout not restored after success: %v", got)
	}
	b := netip.MustParseAddr("192.0.2.2")
	for i := 0; i < 20; i++ {
		in.success(b, time.Duration(100+400*(i%2))*time.Millisecond)
	}
	if got := in.timeout(b); got <= 4*300*time.Millisecond/2 {
		t.Fatalf("jittery server timeout %v does not reflect variance", got)
	}
}

func TestQNameMinimization(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("deep.a.b.c.example.com.", dns.TypeA, false))
	root := netip.MustParseAddr(addrRoot)
	com := netip.MustParseAddr(addrCom)
	for _, q := range e.net.queries() {
		if q.addr == root && q.name != "com." && q.name != "." {
			t.Fatalf("root saw %s", q.name)
		}
		if q.addr == com && q.name != "example.com." && q.name != "com." {
			t.Fatalf("com saw %s", q.name)
		}
	}

	resp := resolve(t, r, query("a.b.broken.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("non-strict fallback failed: %v", resp)
	}
}

func TestQNameMinimizationDisabled(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver(func(o *Opts) { o.DisableQNameMin = true })
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if e.net.count(func(q fakeQuery) bool { return q.addr == netip.MustParseAddr(addrRoot) && q.name == "www.example.com." }) == 0 {
		t.Fatal("full name not sent to root with minimization disabled")
	}
}

func TestTTLAndExpiry(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if ttl := answerOf(resp, dns.TypeA)[0].Header().Ttl; ttl != 300 {
		t.Fatalf("ttl %d", ttl)
	}
	e.net.reset()
	e.clock.Advance(100 * time.Second)
	resp = resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if ttl := answerOf(resp, dns.TypeA)[0].Header().Ttl; ttl != 200 {
		t.Fatalf("ttl after 100s: %d", ttl)
	}
	if len(e.net.queries()) != 0 {
		t.Fatal("cached answer caused network queries")
	}
	e.clock.Advance(201 * time.Second)
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	if e.net.countTo(addrExampleCom)+e.net.countTo(addrLame) == 0 {
		t.Fatal("expired answer was not refreshed")
	}
}

func TestNegativeCache(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resolve(t, r, query("nope.example.com.", dns.TypeA, true))
	e.net.reset()
	resp := resolve(t, r, query("nope.example.com.", dns.TypeAAAA, true))
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	if len(e.net.queries()) != 0 {
		t.Fatal("negative answer was not cached")
	}
}

func TestSingleflight(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).delay = 100 * time.Millisecond
	e.net.server(addrLame).refuse = false
	e.net.server(addrLame).zones = e.net.server(addrExampleCom).zones
	e.net.server(addrLame).delay = 100 * time.Millisecond
	r := e.resolver()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := r.Resolve(ctx, query("other.example.com.", dns.TypeA, false)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	n := e.net.count(func(q fakeQuery) bool { return q.name == "other.example.com." })
	if n != 1 {
		t.Fatalf("expected one upstream query, got %d", n)
	}
}

func TestContextCancel(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrRoot).timeout = true
	r := e.resolver()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Resolve(ctx, query("www.example.com.", dns.TypeA, false))
	if err == nil {
		t.Fatal("expected an error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("resolve did not return after the context deadline")
	}
}

func TestNotImplemented(t *testing.T) {
	e := newTestEnv(t)
	r := e.resolver()
	resp := resolve(t, r, query("example.com.", dns.TypeAXFR, false))
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	q := query("example.com.", dns.TypeA, false)
	q.Question[0].Qclass = dns.ClassCHAOS
	if resp := resolve(t, r, q); resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
}
