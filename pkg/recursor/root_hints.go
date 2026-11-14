package recursor

import (
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

const builtinRootHints = `
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
B.ROOT-SERVERS.NET.      3600000      AAAA  2801:1b8:10::b
.                        3600000      NS    C.ROOT-SERVERS.NET.
C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
C.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2::c
.                        3600000      NS    D.ROOT-SERVERS.NET.
D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13
D.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2d::d
.                        3600000      NS    E.ROOT-SERVERS.NET.
E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
E.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:a8::e
.                        3600000      NS    F.ROOT-SERVERS.NET.
F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2f::f
.                        3600000      NS    G.ROOT-SERVERS.NET.
G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
G.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:12::d0d
.                        3600000      NS    H.ROOT-SERVERS.NET.
H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53
H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::53
.                        3600000      NS    I.ROOT-SERVERS.NET.
I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fe::53
.                        3600000      NS    J.ROOT-SERVERS.NET.
J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:c27::2:30
.                        3600000      NS    K.ROOT-SERVERS.NET.
K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fd::1
.                        3600000      NS    L.ROOT-SERVERS.NET.
L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:9f::42
.                        3600000      NS    M.ROOT-SERVERS.NET.
M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33
M.ROOT-SERVERS.NET.      3600000      AAAA  2001:dc3::35
`

func ParseRRs(r io.Reader, origin string) ([]dns.RR, error) {
	zp := dns.NewZoneParser(r, origin, "")
	zp.SetDefaultTTL(3600)
	var rrs []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return rrs, nil
}

func ReadRRFile(path string) ([]dns.RR, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseRRs(f, ".")
}

func mustParseRRs(s string) []dns.RR {
	rrs, err := ParseRRs(strings.NewReader(s), ".")
	if err != nil {
		panic(err)
	}
	return rrs
}

type rootHints struct {
	ns    []dns.RR
	addrs map[string][]netip.Addr
	set   map[netip.Addr]bool
}

func (h *rootHints) has(a netip.Addr) bool {
	return h.set[a]
}

func newRootHints(rrs []dns.RR) (*rootHints, error) {
	h := &rootHints{addrs: make(map[string][]netip.Addr), set: make(map[netip.Addr]bool)}
	for _, rr := range rrs {
		switch x := rr.(type) {
		case *dns.NS:
			if x.Hdr.Name != "." {
				continue
			}
			ns := &dns.NS{Hdr: x.Hdr, Ns: dns.CanonicalName(x.Ns)}
			ns.Hdr.Ttl = 3600
			h.ns = append(h.ns, ns)
		case *dns.A:
			if a, ok := netip.AddrFromSlice(x.A.To4()); ok {
				n := dns.CanonicalName(x.Hdr.Name)
				h.addrs[n] = append(h.addrs[n], a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(x.AAAA.To16()); ok {
				n := dns.CanonicalName(x.Hdr.Name)
				h.addrs[n] = append(h.addrs[n], a)
			}
		}
	}
	if len(h.ns) == 0 {
		return nil, errNoRootHints
	}
	for _, as := range h.addrs {
		for _, a := range as {
			h.set[a.Unmap()] = true
		}
	}
	return h, nil
}
