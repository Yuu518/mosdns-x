package recursor

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

type fakeQuery struct {
	addr  netip.Addr
	name  string
	qtype uint16
	proto proto
	edns  bool
	ecs   bool
}

type fakeServer struct {
	zones       []*dnssectest.Zone
	timeout     bool
	refuse      bool
	truncate    bool
	formerrEDNS bool
	formerrECS  bool
	ecsScope    uint8
	stripSigs   bool
	tamper      bool
	delay       time.Duration
	inject      []dns.RR
	dot         bool
	dotBreak    bool
	handler     func(q *dns.Msg) *dns.Msg
}

type fakeNet struct {
	mu      sync.Mutex
	servers map[netip.Addr]*fakeServer
	log     []fakeQuery
	probes  atomic.Int64
}

func newFakeNet() *fakeNet {
	return &fakeNet{servers: make(map[netip.Addr]*fakeServer)}
}

func (n *fakeNet) add(addr string, s *fakeServer) *fakeServer {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.servers[netip.MustParseAddr(addr)] = s
	return s
}

func (n *fakeNet) server(addr string) *fakeServer {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.servers[netip.MustParseAddr(addr)]
}

func (n *fakeNet) queries() []fakeQuery {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]fakeQuery(nil), n.log...)
}

func (n *fakeNet) reset() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.log = nil
}

func (n *fakeNet) count(f func(q fakeQuery) bool) int {
	c := 0
	for _, q := range n.queries() {
		if f(q) {
			c++
		}
	}
	return c
}

func (n *fakeNet) countTo(addr string) int {
	a := netip.MustParseAddr(addr)
	return n.count(func(q fakeQuery) bool { return q.addr == a })
}

func pickZone(zones []*dnssectest.Zone, qname string, qtype uint16) *dnssectest.Zone {
	var best *dnssectest.Zone
	for _, z := range zones {
		if !dns.IsSubDomain(z.Origin, qname) {
			continue
		}
		if qtype == dns.TypeDS && z.Origin == qname && qname != "." {
			continue
		}
		if best == nil || dns.CountLabel(z.Origin) > dns.CountLabel(best.Origin) {
			best = z
		}
	}
	return best
}

func (n *fakeNet) exchange(ctx context.Context, addr netip.Addr, q *dns.Msg, p proto) (*dns.Msg, error) {
	opt := q.IsEdns0()
	fq := fakeQuery{addr: addr, name: q.Question[0].Name, qtype: q.Question[0].Qtype, proto: p, edns: opt != nil}
	if opt != nil {
		fq.ecs = dnsutils.GetECS(opt) != nil
	}
	n.mu.Lock()
	s := n.servers[addr]
	n.log = append(n.log, fq)
	n.mu.Unlock()

	if s == nil || s.timeout {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if p == protoDoT && (!s.dot || s.dotBreak) {
		return nil, errors.New("fake: dot connection refused")
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	reply := func(rcode int) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetRcode(q, rcode)
		return m, nil
	}
	if s.refuse {
		return reply(dns.RcodeRefused)
	}
	if opt != nil && (s.formerrEDNS || (s.formerrECS && dnsutils.GetECS(opt) != nil)) {
		return reply(dns.RcodeFormatError)
	}
	var resp *dns.Msg
	if s.handler != nil {
		resp = s.handler(q)
	} else {
		z := pickZone(s.zones, dns.CanonicalName(q.Question[0].Name), q.Question[0].Qtype)
		if z == nil {
			return reply(dns.RcodeRefused)
		}
		resp = z.Answer(q)
	}
	if resp == nil {
		return reply(dns.RcodeServerFailure)
	}
	wire, err := resp.Pack()
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		return nil, err
	}
	out.Id = q.Id
	if s.stripSigs {
		out.Answer = stripType(out.Answer, dns.TypeRRSIG)
		out.Ns = stripType(out.Ns, dns.TypeRRSIG)
	}
	if s.tamper {
		for _, rr := range out.Answer {
			if a, ok := rr.(*dns.A); ok {
				a.A = a.A.To4()
				a.A[3] ^= 0xff
			}
		}
	}
	out.Answer = append(out.Answer, s.inject...)
	out.Extra = append(out.Extra, s.inject...)
	if s.ecsScope > 0 && opt != nil {
		if e := dnsutils.GetECS(opt); e != nil {
			c := *e
			c.SourceScope = s.ecsScope
			if ro := out.IsEdns0(); ro != nil {
				ro.Option = append(ro.Option, &c)
			}
		}
	}
	if s.truncate && p == protoUDP {
		tc := new(dns.Msg)
		tc.SetReply(q)
		tc.Truncated = true
		return tc, nil
	}
	return out, nil
}

func stripType(rrs []dns.RR, t uint16) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if rr.Header().Rrtype != t {
			out = append(out, rr)
		}
	}
	return out
}

func (n *fakeNet) probeDoT(ctx context.Context, addr netip.Addr) error {
	n.probes.Add(1)
	n.mu.Lock()
	s := n.servers[addr]
	n.mu.Unlock()
	if s != nil && s.dot {
		return nil
	}
	return errors.New("fake: no dot")
}

func (n *fakeNet) close() error {
	return nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

const (
	addrRoot       = "10.0.0.1"
	addrCom        = "10.0.1.1"
	addrOrg        = "10.0.2.1"
	addrExampleCom = "10.0.3.1"
	addrLame       = "10.0.3.2"
	addrInsecure   = "10.0.4.1"
	addrExampleOrg = "10.0.5.1"
	addrBroken     = "10.0.6.1"
	addrUnsup      = "10.0.7.1"
	addrBadDS      = "10.0.8.1"
)

type testEnv struct {
	t       *testing.T
	net     *fakeNet
	clock   *fakeClock
	keys    map[string]*dnssectest.Key
	zones   map[string]*dnssectest.Zone
	hints   []dns.RR
	anchors []dns.RR
}

func zoneText(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{
		t:     t,
		net:   newFakeNet(),
		clock: &fakeClock{now: time.Now()},
		keys:  make(map[string]*dnssectest.Key),
		zones: make(map[string]*dnssectest.Zone),
	}
	for _, z := range []string{".", "com.", "org.", "example.com.", "example.org.", "unsup.com.", "badds.com."} {
		e.keys[z] = dnssectest.NewKey(z)
	}

	root := dnssectest.NewZone(".", zoneText(
		". 86400 SOA a.root. admin.root. 2024010100 1800 900 604800 86400",
		". 518400 NS a.root.",
		"a.root. 518400 A "+addrRoot,
		"com. 172800 NS ns.com.",
		"ns.com. 172800 A "+addrCom,
		"org. 172800 NS ns.org.",
		"ns.org. 172800 A "+addrOrg,
	))
	root.Add(e.keys["com."].DS(), e.keys["org."].DS())

	com := dnssectest.NewZone("com.", zoneText(
		"com. 900 SOA ns.com. admin.com. 1 1800 900 604800 86400",
		"com. 172800 NS ns.com.",
		"ns.com. 172800 A "+addrCom,
		"example.com. 172800 NS ns1.example.com.",
		"example.com. 172800 NS lame.example.com.",
		"ns1.example.com. 172800 A "+addrExampleCom,
		"lame.example.com. 172800 A "+addrLame,
		"insecure.com. 172800 NS ns.insecure.com.",
		"ns.insecure.com. 172800 A "+addrInsecure,
		"noglue.com. 172800 NS ns.example.org.",
		"loopa.com. 172800 NS ns.loopb.com.",
		"loopb.com. 172800 NS ns.loopa.com.",
		"broken.com. 172800 NS ns.broken.com.",
		"ns.broken.com. 172800 A "+addrBroken,
		"unsup.com. 172800 NS ns.unsup.com.",
		"ns.unsup.com. 172800 A "+addrUnsup,
		"badds.com. 172800 NS ns.badds.com.",
		"ns.badds.com. 172800 A "+addrBadDS,
	))
	com.Add(e.keys["example.com."].DS())
	unsupDS := e.keys["unsup.com."].DS()
	unsupDS.Algorithm = dns.PRIVATEDNS
	com.Add(unsupDS)
	com.Add(dnssectest.NewKey("badds.com.").DS())

	org := dnssectest.NewZone("org.", zoneText(
		"org. 900 SOA ns.org. admin.org. 1 1800 900 604800 86400",
		"org. 172800 NS ns.org.",
		"ns.org. 172800 A "+addrOrg,
		"example.org. 172800 NS ns.example.org.",
		"ns.example.org. 172800 A "+addrExampleOrg,
	))
	org.Add(e.keys["example.org."].DS())

	exampleCom := dnssectest.NewZone("example.com.", zoneText(
		"example.com. 3600 SOA ns1.example.com. admin.example.com. 1 3600 600 86400 300",
		"example.com. 3600 NS ns1.example.com.",
		"example.com. 3600 NS lame.example.com.",
		"ns1.example.com. 3600 A "+addrExampleCom,
		"lame.example.com. 3600 A "+addrLame,
		"www.example.com. 300 A 192.0.2.1",
		"www.example.com. 300 AAAA 2001:db8::1",
		"other.example.com. 300 A 192.0.2.2",
		"cname.example.com. 300 CNAME www.example.org.",
		"loop1.example.com. 300 CNAME loop2.example.com.",
		"loop2.example.com. 300 CNAME loop1.example.com.",
		"*.wild.example.com. 300 A 192.0.2.9",
		"dn.example.com. 300 DNAME example.org.",
		"deep.a.b.c.example.com. 300 A 192.0.2.10",
	))

	exampleOrg := dnssectest.NewZone("example.org.", zoneText(
		"example.org. 3600 SOA ns.example.org. admin.example.org. 1 3600 600 86400 300",
		"example.org. 3600 NS ns.example.org.",
		"ns.example.org. 3600 A "+addrExampleOrg,
		"www.example.org. 300 A 192.0.2.20",
	))

	insecure := dnssectest.NewZone("insecure.com.", zoneText(
		"insecure.com. 3600 SOA ns.insecure.com. admin.insecure.com. 1 3600 600 86400 300",
		"insecure.com. 3600 NS ns.insecure.com.",
		"ns.insecure.com. 3600 A "+addrInsecure,
		"www.insecure.com. 300 A 192.0.2.30",
	))

	noglue := dnssectest.NewZone("noglue.com.", zoneText(
		"noglue.com. 3600 SOA ns.example.org. admin.noglue.com. 1 3600 600 86400 300",
		"noglue.com. 3600 NS ns.example.org.",
		"www.noglue.com. 300 A 192.0.2.40",
	))

	broken := dnssectest.NewZone("broken.com.", zoneText(
		"broken.com. 3600 SOA ns.broken.com. admin.broken.com. 1 3600 600 86400 300",
		"broken.com. 3600 NS ns.broken.com.",
		"ns.broken.com. 3600 A "+addrBroken,
		"a.b.broken.com. 300 A 192.0.2.50",
	))

	unsup := dnssectest.NewZone("unsup.com.", zoneText(
		"unsup.com. 3600 SOA ns.unsup.com. admin.unsup.com. 1 3600 600 86400 300",
		"unsup.com. 3600 NS ns.unsup.com.",
		"ns.unsup.com. 3600 A "+addrUnsup,
		"www.unsup.com. 300 A 192.0.2.60",
	))

	baddsZone := dnssectest.NewZone("badds.com.", zoneText(
		"badds.com. 3600 SOA ns.badds.com. admin.badds.com. 1 3600 600 86400 300",
		"badds.com. 3600 NS ns.badds.com.",
		"ns.badds.com. 3600 A "+addrBadDS,
		"www.badds.com. 300 A 192.0.2.70",
	))

	root.Sign(e.keys["."], dnssectest.DenialNSEC)
	com.Sign(e.keys["com."], dnssectest.DenialNSEC3OptOut)
	org.Sign(e.keys["org."], dnssectest.DenialNSEC)
	exampleCom.Sign(e.keys["example.com."], dnssectest.DenialNSEC)
	exampleOrg.Sign(e.keys["example.org."], dnssectest.DenialNSEC3)
	unsup.Sign(e.keys["unsup.com."], dnssectest.DenialNSEC)
	baddsZone.Sign(e.keys["badds.com."], dnssectest.DenialNSEC)

	for _, z := range []*dnssectest.Zone{root, com, org, exampleCom, exampleOrg, insecure, noglue, broken, unsup, baddsZone} {
		e.zones[z.Origin] = z
	}

	e.net.add(addrRoot, &fakeServer{zones: []*dnssectest.Zone{root}})
	e.net.add(addrCom, &fakeServer{zones: []*dnssectest.Zone{com}})
	e.net.add(addrOrg, &fakeServer{zones: []*dnssectest.Zone{org}})
	e.net.add(addrExampleCom, &fakeServer{zones: []*dnssectest.Zone{exampleCom}})
	e.net.add(addrLame, &fakeServer{refuse: true})
	e.net.add(addrInsecure, &fakeServer{zones: []*dnssectest.Zone{insecure}})
	e.net.add(addrExampleOrg, &fakeServer{zones: []*dnssectest.Zone{exampleOrg, noglue}})
	e.net.add(addrBroken, &fakeServer{handler: func(q *dns.Msg) *dns.Msg {
		if dns.CanonicalName(q.Question[0].Name) == "b.broken.com." {
			r := broken.Answer(q)
			r.Rcode = dns.RcodeNameError
			return r
		}
		return broken.Answer(q)
	}})
	e.net.add(addrUnsup, &fakeServer{zones: []*dnssectest.Zone{unsup}})
	e.net.add(addrBadDS, &fakeServer{zones: []*dnssectest.Zone{baddsZone}})

	e.hints = mustParseRRs(". 3600000 NS a.root.\na.root. 3600000 A " + addrRoot + "\n")
	e.anchors = []dns.RR{e.keys["."].DS()}
	return e
}

func (e *testEnv) opts() Opts {
	return Opts{
		RootHints:    e.hints,
		TrustAnchors: e.anchors,
		NoIPv6:       true,
		exchanger:    e.net,
		now:          e.clock.Now,
	}
}

func (e *testEnv) resolver(mod ...func(o *Opts)) *Resolver {
	e.t.Helper()
	o := e.opts()
	for _, f := range mod {
		f(&o)
	}
	r, err := New(o)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { r.Close() })
	return r
}

func query(name string, qtype uint16, do bool) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.SetEdns0(1232, do)
	return q
}

func resolve(t *testing.T, r *Resolver, q *dns.Msg) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.Resolve(ctx, q)
	if err != nil {
		t.Fatalf("resolve %s %s: %v", q.Question[0].Name, dns.TypeToString[q.Question[0].Qtype], err)
	}
	return resp
}

func answerOf(m *dns.Msg, t uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			out = append(out, rr)
		}
	}
	return out
}

func edeOf(m *dns.Msg) (uint16, bool) {
	opt := m.IsEdns0()
	if opt == nil {
		return 0, false
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			return e.InfoCode, true
		}
	}
	return 0, false
}

func hasType(rrs []dns.RR, t uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}
