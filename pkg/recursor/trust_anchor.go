package recursor

import (
	"github.com/miekg/dns"
)

const builtinTrustAnchors = `
. 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
. 172800 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
`

func parseTrustAnchors(rrs []dns.RR) ([]*dns.DS, error) {
	var out []*dns.DS
	for _, rr := range rrs {
		switch x := rr.(type) {
		case *dns.DS:
			if x.Hdr.Name == "." {
				out = append(out, x)
			}
		case *dns.DNSKEY:
			if x.Hdr.Name == "." {
				if ds := x.ToDS(dns.SHA256); ds != nil {
					out = append(out, ds)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, errNoTrustAnchor
	}
	return out, nil
}
