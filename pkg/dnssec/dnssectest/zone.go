package dnssectest

import (
	"crypto"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
)

type Key struct {
	DNSKEY *dns.DNSKEY
	Signer crypto.Signer
}

func NewKey(zone string) *Key {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.CanonicalName(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	for {
		priv, err := k.Generate(256)
		if err != nil {
			panic(err)
		}
		r := *k
		r.Flags |= dns.REVOKE
		if k.KeyTag() != 0 && r.KeyTag() != 0 {
			return &Key{DNSKEY: k, Signer: priv.(crypto.Signer)}
		}
	}
}

func (k *Key) DS() *dns.DS {
	return k.DNSKEY.ToDS(dns.SHA256)
}

func (k *Key) Sign(rrset []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: rrset[0].Header().Ttl},
		Algorithm:  k.DNSKEY.Algorithm,
		KeyTag:     k.DNSKEY.KeyTag(),
		SignerName: k.DNSKEY.Hdr.Name,
		Inception:  uint32(inception.Unix()),
		Expiration: uint32(expiration.Unix()),
	}
	if err := sig.Sign(k.Signer, rrset); err != nil {
		panic(err)
	}
	return sig
}

type Denial int

const (
	DenialNSEC Denial = iota
	DenialNSEC3
	DenialNSEC3OptOut
)

type Zone struct {
	Origin     string
	Key        *Key
	Denial     Denial
	Iterations uint16
	Salt       string
	Inception  time.Time
	Expiration time.Time

	data   map[string]map[uint16][]dns.RR
	sigs   map[string]map[uint16][]*dns.RRSIG
	nsecs  []*dns.NSEC
	nsec3s []*dns.NSEC3
}

func NewZone(origin, text string) *Zone {
	z := &Zone{
		Origin: dns.CanonicalName(origin),
		data:   make(map[string]map[uint16][]dns.RR),
		sigs:   make(map[string]map[uint16][]*dns.RRSIG),
	}
	zp := dns.NewZoneParser(strings.NewReader(text), z.Origin, "")
	zp.SetDefaultTTL(3600)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		z.Add(rr)
	}
	if err := zp.Err(); err != nil {
		panic(err)
	}
	return z
}

func (z *Zone) Add(rrs ...dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		h.Name = dns.CanonicalName(h.Name)
		m := z.data[h.Name]
		if m == nil {
			m = make(map[uint16][]dns.RR)
			z.data[h.Name] = m
		}
		m[h.Rrtype] = append(m[h.Rrtype], rr)
	}
}

func (z *Zone) AddText(text string) {
	zp := dns.NewZoneParser(strings.NewReader(text), z.Origin, "")
	zp.SetDefaultTTL(3600)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		z.Add(rr)
	}
	if err := zp.Err(); err != nil {
		panic(err)
	}
}

func (z *Zone) Remove(name string, t uint16) {
	name = dns.CanonicalName(name)
	if m := z.data[name]; m != nil {
		delete(m, t)
		if len(m) == 0 {
			delete(z.data, name)
		}
	}
}

func (z *Zone) Get(name string, t uint16) []dns.RR {
	return z.data[dns.CanonicalName(name)][t]
}

func (z *Zone) Sigs(name string, t uint16) []*dns.RRSIG {
	return z.sigs[dns.CanonicalName(name)][t]
}

func (z *Zone) SetSigs(name string, t uint16, sigs []*dns.RRSIG) {
	name = dns.CanonicalName(name)
	if z.sigs[name] == nil {
		z.sigs[name] = make(map[uint16][]*dns.RRSIG)
	}
	z.sigs[name][t] = sigs
}

func (z *Zone) SOA() *dns.SOA {
	if rrs := z.Get(z.Origin, dns.TypeSOA); len(rrs) > 0 {
		return rrs[0].(*dns.SOA)
	}
	return nil
}

func (z *Zone) Signed() bool {
	return z.Key != nil
}

func (z *Zone) isCut(name string) bool {
	return name != z.Origin && len(z.data[name][dns.TypeNS]) > 0
}

func (z *Zone) isGlue(name string) bool {
	for n := dnssec.ParentName(name); dns.IsSubDomain(z.Origin, n) && n != z.Origin; n = dnssec.ParentName(n) {
		if z.isCut(n) {
			return true
		}
	}
	return false
}

func (z *Zone) authNames() []string {
	var names []string
	for n := range z.data {
		if z.isGlue(n) {
			continue
		}
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return dnssec.CompareNames(names[i], names[j]) < 0 })
	return names
}

func (z *Zone) Sign(key *Key, denial Denial) {
	z.Key = key
	z.Denial = denial
	if z.Inception.IsZero() {
		z.Inception = time.Now().Add(-24 * time.Hour)
	}
	if z.Expiration.IsZero() {
		z.Expiration = time.Now().Add(30 * 24 * time.Hour)
	}
	z.Resign()
}

func sortedTypes(m map[uint16][]dns.RR, extra ...uint16) []uint16 {
	seen := make(map[uint16]bool)
	var ts []uint16
	for t := range m {
		if !seen[t] {
			seen[t] = true
			ts = append(ts, t)
		}
	}
	for _, t := range extra {
		if !seen[t] {
			seen[t] = true
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	return ts
}

func (z *Zone) Resign() {
	if z.Key == nil {
		return
	}
	for _, t := range []uint16{dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeNSEC3PARAM} {
		z.Remove(z.Origin, t)
	}
	for n, m := range z.data {
		delete(m, dns.TypeNSEC)
		delete(m, dns.TypeNSEC3)
		if len(m) == 0 {
			delete(z.data, n)
		}
	}
	z.sigs = make(map[string]map[uint16][]*dns.RRSIG)
	z.nsecs = nil
	z.nsec3s = nil
	k := *z.Key.DNSKEY
	k.Hdr.Name = z.Origin
	z.Add(&k)

	soaTTL := uint32(3600)
	if soa := z.SOA(); soa != nil {
		soaTTL = soa.Minttl
	}
	names := z.authNames()

	switch z.Denial {
	case DenialNSEC:
		for i, n := range names {
			next := names[(i+1)%len(names)]
			var ts []uint16
			if z.isCut(n) {
				ts = []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}
				if len(z.data[n][dns.TypeDS]) > 0 {
					ts = append(ts, dns.TypeDS)
				}
				sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
			} else {
				ts = sortedTypes(z.data[n], dns.TypeRRSIG, dns.TypeNSEC)
			}
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: n, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: soaTTL},
				NextDomain: next,
				TypeBitMap: ts,
			}
			z.nsecs = append(z.nsecs, nsec)
		}
		for _, nsec := range z.nsecs {
			z.Add(nsec)
		}
	default:
		z.Add(&dns.NSEC3PARAM{
			Hdr:        dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0},
			Hash:       dns.SHA1,
			Iterations: z.Iterations,
			SaltLength: uint8(len(z.Salt) / 2),
			Salt:       z.Salt,
		})
		optOut := z.Denial == DenialNSEC3OptOut
		all := make(map[string]bool)
		for _, n := range names {
			if optOut && z.isCut(n) && len(z.data[n][dns.TypeDS]) == 0 {
				continue
			}
			all[n] = true
			for p := dnssec.ParentName(n); p != z.Origin && dns.IsSubDomain(z.Origin, p); p = dnssec.ParentName(p) {
				if _, ok := all[p]; !ok {
					all[p] = false
				}
			}
		}
		type h3 struct {
			hash string
			name string
		}
		var hs []h3
		for n := range all {
			hs = append(hs, h3{hash: dns.HashName(n, dns.SHA1, z.Iterations, z.Salt), name: n})
		}
		sort.Slice(hs, func(i, j int) bool { return hs[i].hash < hs[j].hash })
		var flags uint8
		if optOut {
			flags = 1
		}
		for i, h := range hs {
			next := hs[(i+1)%len(hs)].hash
			var ts []uint16
			_, exists := z.data[h.name]
			switch {
			case !exists:
			case z.isCut(h.name):
				ts = []uint16{dns.TypeNS}
				if len(z.data[h.name][dns.TypeDS]) > 0 {
					ts = append(ts, dns.TypeDS, dns.TypeRRSIG)
				}
				sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
			default:
				ts = sortedTypes(z.data[h.name], dns.TypeRRSIG)
			}
			owner := strings.ToLower(h.hash) + "." + z.Origin
			if z.Origin == "." {
				owner = strings.ToLower(h.hash) + "."
			}
			n3 := &dns.NSEC3{
				Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: soaTTL},
				Hash:       dns.SHA1,
				Flags:      flags,
				Iterations: z.Iterations,
				SaltLength: uint8(len(z.Salt) / 2),
				Salt:       z.Salt,
				HashLength: 20,
				NextDomain: next,
				TypeBitMap: ts,
			}
			z.nsec3s = append(z.nsec3s, n3)
		}
		for _, n3 := range z.nsec3s {
			z.Add(n3)
		}
	}

	for n, m := range z.data {
		if z.isGlue(n) {
			continue
		}
		for t, rrs := range m {
			if z.isCut(n) && t != dns.TypeDS && t != dns.TypeNSEC {
				continue
			}
			z.SetSigs(n, t, []*dns.RRSIG{z.Key.Sign(rrs, z.Inception, z.Expiration)})
		}
	}
}

func (z *Zone) AddZONEMD() {
	soa := z.SOA()
	z.Remove(z.Origin, dns.TypeZONEMD)
	md := &dns.ZONEMD{
		Hdr:    dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeZONEMD, Class: dns.ClassINET, Ttl: soa.Hdr.Ttl},
		Serial: soa.Serial,
		Scheme: 1,
		Hash:   1,
		Digest: strings.Repeat("00", 48),
	}
	z.Add(md)
	z.Resign()
	d, err := dnssec.ZoneDigest(z.Records(), z.Origin, 1)
	if err != nil {
		panic(err)
	}
	md.Digest = hex.EncodeToString(d)
	if z.Key != nil {
		z.SetSigs(z.Origin, dns.TypeZONEMD, []*dns.RRSIG{z.Key.Sign([]dns.RR{md}, z.Inception, z.Expiration)})
	}
}

func (z *Zone) Records() []dns.RR {
	var out []dns.RR
	for n, m := range z.data {
		for t, rrs := range m {
			out = append(out, rrs...)
			for _, s := range z.sigs[n][t] {
				out = append(out, s)
			}
		}
	}
	return out
}

func (z *Zone) Text() string {
	var b strings.Builder
	for _, rr := range z.Records() {
		b.WriteString(rr.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func (z *Zone) NSECs() []*dns.NSEC {
	return z.nsecs
}

func (z *Zone) NSEC3s() []*dns.NSEC3 {
	return z.nsec3s
}
