package dnssec_test

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
)

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

func TestCompareNames(t *testing.T) {
	ordered := []string{
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"z.example.",
		"\\001.z.example.",
		"*.z.example.",
		"\\200.z.example.",
	}
	for i := 0; i < len(ordered); i++ {
		for j := 0; j < len(ordered); j++ {
			got := dnssec.CompareNames(ordered[i], ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Fatalf("CompareNames(%q, %q) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
}

func TestVerifyRRset(t *testing.T) {
	now := time.Now()
	k := dnssectest.NewKey("example.")
	keys := []*dns.DNSKEY{k.DNSKEY}
	rrset := []dns.RR{mustRR("www.example. 300 IN A 192.0.2.1"), mustRR("www.example. 300 IN A 192.0.2.2")}
	good := k.Sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	if _, err := dnssec.VerifyRRset(rrset, []*dns.RRSIG{good}, keys, now, nil); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tampered := []dns.RR{mustRR("www.example. 300 IN A 192.0.2.1"), mustRR("www.example. 300 IN A 192.0.2.3")}
	if _, err := dnssec.VerifyRRset(tampered, []*dns.RRSIG{good}, keys, now, nil); !errors.Is(err, dnssec.ErrBadSignature) {
		t.Fatalf("tampered rrset: got %v", err)
	}

	expired := k.Sign(rrset, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := dnssec.VerifyRRset(rrset, []*dns.RRSIG{expired}, keys, now, nil); !errors.Is(err, dnssec.ErrExpired) {
		t.Fatalf("expired: got %v", err)
	}

	future := k.Sign(rrset, now.Add(time.Hour), now.Add(2*time.Hour))
	if _, err := dnssec.VerifyRRset(rrset, []*dns.RRSIG{future}, keys, now, nil); !errors.Is(err, dnssec.ErrNotYetValid) {
		t.Fatalf("not yet valid: got %v", err)
	}

	other := dnssectest.NewKey("other.")
	foreign := other.Sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := dnssec.VerifyRRset(rrset, []*dns.RRSIG{foreign}, []*dns.DNSKEY{other.DNSKEY}, now, nil); !errors.Is(err, dnssec.ErrBadSignature) {
		t.Fatalf("signer not an ancestor: got %v", err)
	}

	if _, err := dnssec.VerifyRRset(rrset, []*dns.RRSIG{good}, []*dns.DNSKEY{dnssectest.NewKey("example.").DNSKEY}, now, nil); !errors.Is(err, dnssec.ErrNoKey) {
		t.Fatalf("no matching key: got %v", err)
	}

	if _, err := dnssec.VerifyRRset(rrset, nil, keys, now, nil); !errors.Is(err, dnssec.ErrNoSignature) {
		t.Fatalf("no signature: got %v", err)
	}

	unsupported := *good
	unsupported.Algorithm = dns.ED448
	if _, err := dnssec.VerifyRRset(rrset, []*dns.RRSIG{&unsupported}, keys, now, nil); !errors.Is(err, dnssec.ErrUnsupported) {
		t.Fatalf("unsupported algorithm: got %v", err)
	}
}

func TestVerifyRRsetKeyTagLimit(t *testing.T) {
	now := time.Now()
	k := dnssectest.NewKey("example.")
	rrset := []dns.RR{mustRR("www.example. 300 IN A 192.0.2.1")}
	sig := k.Sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	tampered := []dns.RR{mustRR("www.example. 300 IN A 192.0.2.9")}
	var keys []*dns.DNSKEY
	for i := 0; i < 8; i++ {
		c := *k.DNSKEY
		keys = append(keys, &c)
	}

	if _, err := dnssec.VerifyRRset(tampered, []*dns.RRSIG{sig}, keys, now, dnssec.NewBudget(4)); !errors.Is(err, dnssec.ErrBadSignature) {
		t.Fatalf("expected at most 4 attempts per key tag, got %v", err)
	}
	if _, err := dnssec.VerifyRRset(tampered, []*dns.RRSIG{sig}, keys, now, dnssec.NewBudget(3)); !errors.Is(err, dnssec.ErrBudget) {
		t.Fatalf("expected budget exhaustion, got %v", err)
	}
}

func TestVerifyDNSKEYs(t *testing.T) {
	now := time.Now()
	k := dnssectest.NewKey("example.")
	keys := []*dns.DNSKEY{k.DNSKEY}
	sig := k.Sign([]dns.RR{k.DNSKEY}, now.Add(-time.Hour), now.Add(time.Hour))
	sigs := []*dns.RRSIG{sig}

	if err := dnssec.VerifyDNSKEYs(keys, sigs, []*dns.DS{k.DS()}, now, nil); err != nil {
		t.Fatalf("matching ds rejected: %v", err)
	}

	bad := *k.DS()
	bad.Digest = "00" + bad.Digest[2:]
	if err := dnssec.VerifyDNSKEYs(keys, sigs, []*dns.DS{&bad}, now, nil); !errors.Is(err, dnssec.ErrDSMismatch) {
		t.Fatalf("mismatching ds: got %v", err)
	}

	unsupported := *k.DS()
	unsupported.DigestType = dns.GOST94
	if err := dnssec.VerifyDNSKEYs(keys, sigs, []*dns.DS{&unsupported}, now, nil); !errors.Is(err, dnssec.ErrUnsupported) {
		t.Fatalf("unsupported digest: got %v", err)
	}

	unsupportedAlg := *k.DS()
	unsupportedAlg.Algorithm = dns.ED448
	if err := dnssec.VerifyDNSKEYs(keys, sigs, []*dns.DS{&unsupportedAlg}, now, nil); !errors.Is(err, dnssec.ErrUnsupported) {
		t.Fatalf("unsupported algorithm: got %v", err)
	}

	otherSig := dnssectest.NewKey("example.")
	both := []*dns.DNSKEY{k.DNSKEY, otherSig.DNSKEY}
	sigByOther := otherSig.Sign([]dns.RR{k.DNSKEY, otherSig.DNSKEY}, now.Add(-time.Hour), now.Add(time.Hour))
	if err := dnssec.VerifyDNSKEYs(both, []*dns.RRSIG{sigByOther}, []*dns.DS{k.DS()}, now, nil); err == nil {
		t.Fatal("dnskey set not signed by the ds key was accepted")
	}
}
