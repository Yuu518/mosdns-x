package dnssec_test

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
)

const proofZone = `
$ORIGIN example.
@     SOA ns.example. host.example. 1 3600 600 86400 300
@     NS  ns
ns    A   192.0.2.1
a     A   192.0.2.2
x.y   A   192.0.2.3
w     TXT "w"
*.w   TXT "wild"
sub   NS  ns.sub
ns.sub A  192.0.2.4
sec   NS  ns.sec
ns.sec A  192.0.2.5
`

func newProofZone(t *testing.T, denial dnssectest.Denial, iterations uint16) *dnssectest.Zone {
	t.Helper()
	z := dnssectest.NewZone("example.", proofZone)
	z.Add(dnssectest.NewKey("sec.example.").DS())
	z.Iterations = iterations
	z.Sign(dnssectest.NewKey("example."), denial)
	return z
}

func ask(t *testing.T, z *dnssectest.Zone, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.SetEdns0(1232, true)
	return z.Answer(q)
}

func denial(m *dns.Msg) ([]*dns.NSEC, []*dns.NSEC3) {
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, rr := range m.Ns {
		switch x := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, x)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, x)
		}
	}
	return nsecs, nsec3s
}

func TestProofs(t *testing.T) {
	modes := []struct {
		name   string
		denial dnssectest.Denial
		optOut bool
	}{
		{"nsec", dnssectest.DenialNSEC, false},
		{"nsec3", dnssectest.DenialNSEC3, false},
		{"nsec3_optout", dnssectest.DenialNSEC3OptOut, true},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			z := newProofZone(t, mode.denial, 0)

			r := ask(t, z, "nope.example.", dns.TypeA)
			if r.Rcode != dns.RcodeNameError {
				t.Fatalf("expected nxdomain, got %s", dns.RcodeToString[r.Rcode])
			}
			nsecs, nsec3s := denial(r)
			want := dnssec.Proven
			if mode.optOut {
				want = dnssec.ProvenInsecure
			}
			if got := dnssec.ProveNXDomain("nope.example.", nsecs, nsec3s); got != want {
				t.Fatalf("nxdomain proof: got %s, want %s", got, want)
			}
			if got := dnssec.ProveNXDomain("a.example.", nsecs, nsec3s); got != dnssec.NotProven {
				t.Fatalf("nxdomain proof accepted for existing name: %s", got)
			}

			r = ask(t, z, "a.example.", dns.TypeMX)
			nsecs, nsec3s = denial(r)
			if got := dnssec.ProveNoData("a.example.", dns.TypeMX, nsecs, nsec3s); got != dnssec.Proven {
				t.Fatalf("nodata proof: got %s", got)
			}
			if got := dnssec.ProveNoData("a.example.", dns.TypeA, nsecs, nsec3s); got != dnssec.NotProven {
				t.Fatalf("nodata proof accepted for existing type: %s", got)
			}

			r = ask(t, z, "y.example.", dns.TypeA)
			if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
				t.Fatalf("expected empty non-terminal nodata, got %v", r)
			}
			nsecs, nsec3s = denial(r)
			if got := dnssec.ProveNoData("y.example.", dns.TypeA, nsecs, nsec3s); got != dnssec.Proven {
				t.Fatalf("empty non-terminal proof: got %s", got)
			}

			r = ask(t, z, "foo.w.example.", dns.TypeTXT)
			if len(r.Answer) != 2 {
				t.Fatalf("expected wildcard answer, got %v", r)
			}
			sig := r.Answer[1].(*dns.RRSIG)
			nsecs, nsec3s = denial(r)
			if got := dnssec.ProveWildcard("foo.w.example.", sig.Labels, nsecs, nsec3s); got != dnssec.Proven {
				t.Fatalf("wildcard proof: got %s", got)
			}
			if got := dnssec.ProveWildcard("foo.w.example.", sig.Labels, nil, nil); got != dnssec.NotProven {
				t.Fatalf("wildcard proof without denial records: got %s", got)
			}

			r = ask(t, z, "foo.w.example.", dns.TypeMX)
			nsecs, nsec3s = denial(r)
			if got := dnssec.ProveNoData("foo.w.example.", dns.TypeMX, nsecs, nsec3s); got != dnssec.Proven {
				t.Fatalf("wildcard nodata proof: got %s", got)
			}

			r = ask(t, z, "www.sub.example.", dns.TypeA)
			if len(r.Ns) == 0 || r.Authoritative {
				t.Fatalf("expected referral, got %v", r)
			}
			nsecs, nsec3s = denial(r)
			p, deleg := dnssec.ProveNoDS("sub.example.", nsecs, nsec3s)
			wantP := dnssec.Proven
			if mode.optOut {
				wantP = dnssec.ProvenInsecure
			}
			if p != wantP || !deleg {
				t.Fatalf("insecure delegation proof: got %s %v", p, deleg)
			}

			r = ask(t, z, "a.example.", dns.TypeDS)
			nsecs, nsec3s = denial(r)
			p, deleg = dnssec.ProveNoDS("a.example.", nsecs, nsec3s)
			if p != dnssec.Proven || deleg {
				t.Fatalf("no zone cut proof: got %s %v", p, deleg)
			}

			r = ask(t, z, "sec.example.", dns.TypeDS)
			if len(r.Answer) == 0 {
				t.Fatalf("expected ds answer, got %v", r)
			}
		})
	}
}

func TestNSEC3IterationLimit(t *testing.T) {
	z := newProofZone(t, dnssectest.DenialNSEC3, dnssec.MaxNSEC3Iterations+1)
	r := ask(t, z, "nope.example.", dns.TypeA)
	nsecs, nsec3s := denial(r)
	if got := dnssec.ProveNXDomain("nope.example.", nsecs, nsec3s); got != dnssec.ProvenInsecure {
		t.Fatalf("expected insecure for high iteration count, got %s", got)
	}
}

func TestSignedZoneVerifies(t *testing.T) {
	z := newProofZone(t, dnssectest.DenialNSEC, 0)
	now := time.Now()
	r := ask(t, z, "a.example.", dns.TypeA)
	var rrs []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range r.Answer {
		if s, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, s)
		} else {
			rrs = append(rrs, rr)
		}
	}
	if _, err := dnssec.VerifyRRset(rrs, sigs, []*dns.DNSKEY{z.Key.DNSKEY}, now, nil); err != nil {
		t.Fatal(err)
	}
}
