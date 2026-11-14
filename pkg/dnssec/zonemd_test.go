package dnssec_test

import (
	"errors"
	"testing"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
)

const smallRoot = `
$ORIGIN .
@        86400 SOA a.root-servers.net. nstld.verisign-grs.com. 2024010100 1800 900 604800 86400
@        518400 NS a.root-servers.net.
com.     172800 NS a.gtld-servers.net.
a.gtld-servers.net. 172800 A 192.0.2.53
`

func TestZONEMD(t *testing.T) {
	z := dnssectest.NewZone(".", smallRoot)
	z.Sign(dnssectest.NewKey("."), dnssectest.DenialNSEC)
	z.AddZONEMD()
	rrs := z.Records()
	if err := dnssec.VerifyZONEMD(rrs, "."); err != nil {
		t.Fatalf("valid zone rejected: %v", err)
	}

	var tampered []dns.RR
	for _, rr := range rrs {
		if a, ok := rr.(*dns.A); ok {
			c := *a
			c.A = c.A.To4()
			c.A = append(c.A[:3:3], 54)
			tampered = append(tampered, &c)
			continue
		}
		tampered = append(tampered, rr)
	}
	if err := dnssec.VerifyZONEMD(tampered, "."); !errors.Is(err, dnssec.ErrZONEMDMismatch) {
		t.Fatalf("tampered zone: got %v", err)
	}

	var badSerial []dns.RR
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			c := *soa
			c.Serial++
			badSerial = append(badSerial, &c)
			continue
		}
		badSerial = append(badSerial, rr)
	}
	if err := dnssec.VerifyZONEMD(badSerial, "."); !errors.Is(err, dnssec.ErrZONEMDSerial) {
		t.Fatalf("serial mismatch: got %v", err)
	}

	var noMD []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeZONEMD {
			noMD = append(noMD, rr)
		}
	}
	if err := dnssec.VerifyZONEMD(noMD, "."); !errors.Is(err, dnssec.ErrZONEMDMissing) {
		t.Fatalf("missing zonemd: got %v", err)
	}
}
