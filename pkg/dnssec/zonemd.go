package dnssec

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

var (
	ErrZONEMDMissing     = errors.New("dnssec: zone has no usable zonemd record")
	ErrZONEMDMismatch    = errors.New("dnssec: zone digest mismatch")
	ErrZONEMDNoSOA       = errors.New("dnssec: zone has no soa record")
	ErrZONEMDSerial      = errors.New("dnssec: zonemd serial does not match soa serial")
	ErrZONEMDOutOfZone   = errors.New("dnssec: zone contains out of zone data")
	ErrZONEMDUnsupported = errors.New("dnssec: unsupported zonemd scheme or hash")
)

const (
	zonemdSchemeSimple = 1
	zonemdHashSHA384   = 1
	zonemdHashSHA512   = 2
)

func canonicalRR(rr dns.RR) dns.RR {
	c := dns.Copy(rr)
	h := c.Header()
	h.Name = dns.CanonicalName(h.Name)
	switch x := c.(type) {
	case *dns.NS:
		x.Ns = dns.CanonicalName(x.Ns)
	case *dns.CNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.SOA:
		x.Ns = dns.CanonicalName(x.Ns)
		x.Mbox = dns.CanonicalName(x.Mbox)
	case *dns.PTR:
		x.Ptr = dns.CanonicalName(x.Ptr)
	case *dns.MX:
		x.Mx = dns.CanonicalName(x.Mx)
	case *dns.MINFO:
		x.Rmail = dns.CanonicalName(x.Rmail)
		x.Email = dns.CanonicalName(x.Email)
	case *dns.RP:
		x.Mbox = dns.CanonicalName(x.Mbox)
		x.Txt = dns.CanonicalName(x.Txt)
	case *dns.AFSDB:
		x.Hostname = dns.CanonicalName(x.Hostname)
	case *dns.RT:
		x.Host = dns.CanonicalName(x.Host)
	case *dns.PX:
		x.Map822 = dns.CanonicalName(x.Map822)
		x.Mapx400 = dns.CanonicalName(x.Mapx400)
	case *dns.NAPTR:
		x.Replacement = dns.CanonicalName(x.Replacement)
	case *dns.KX:
		x.Exchanger = dns.CanonicalName(x.Exchanger)
	case *dns.SRV:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.DNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.RRSIG:
		x.SignerName = dns.CanonicalName(x.SignerName)
	}
	return c
}

type wireRR struct {
	owner string
	rtype uint16
	rdata []byte
	wire  []byte
}

func zonemdExcluded(rr dns.RR, origin string) bool {
	h := rr.Header()
	if !EqualNames(h.Name, origin) {
		return false
	}
	switch x := rr.(type) {
	case *dns.ZONEMD:
		return true
	case *dns.RRSIG:
		return x.TypeCovered == dns.TypeZONEMD
	}
	return false
}

func newZONEMDHash(alg uint8) (hash.Hash, error) {
	switch alg {
	case zonemdHashSHA384:
		return sha512.New384(), nil
	case zonemdHashSHA512:
		return sha512.New(), nil
	}
	return nil, ErrZONEMDUnsupported
}

func ZoneDigest(rrs []dns.RR, origin string, alg uint8) ([]byte, error) {
	h, err := newZONEMDHash(alg)
	if err != nil {
		return nil, err
	}
	origin = dns.CanonicalName(origin)
	ws := make([]wireRR, 0, len(rrs))
	for _, rr := range rrs {
		hdr := rr.Header()
		if !dns.IsSubDomain(origin, hdr.Name) {
			return nil, ErrZONEMDOutOfZone
		}
		if zonemdExcluded(rr, origin) {
			continue
		}
		c := canonicalRR(rr)
		buf := make([]byte, dns.Len(c)+1)
		n, err := dns.PackRR(c, buf, 0, nil, false)
		if err != nil {
			return nil, fmt.Errorf("pack %s: %w", rr.String(), err)
		}
		buf = buf[:n]
		ownerLen := 0
		for ownerLen < len(buf) && buf[ownerLen] != 0 {
			ownerLen += int(buf[ownerLen]) + 1
		}
		ownerLen++
		rdStart := ownerLen + 10
		if rdStart > len(buf) {
			return nil, fmt.Errorf("bad wire format for %s", rr.String())
		}
		ws = append(ws, wireRR{
			owner: c.Header().Name,
			rtype: c.Header().Rrtype,
			rdata: buf[rdStart:],
			wire:  buf,
		})
	}
	ownerCmp := make(map[string][][]byte)
	labelsOf := func(n string) [][]byte {
		if l, ok := ownerCmp[n]; ok {
			return l
		}
		l := wireLabels(n)
		ownerCmp[n] = l
		return l
	}
	sort.Slice(ws, func(i, j int) bool {
		a, b := ws[i], ws[j]
		if a.owner != b.owner {
			return compareLabels(labelsOf(a.owner), labelsOf(b.owner)) < 0
		}
		if a.rtype != b.rtype {
			return a.rtype < b.rtype
		}
		return bytes.Compare(a.rdata, b.rdata) < 0
	})
	var prev []byte
	for _, w := range ws {
		if prev != nil && bytes.Equal(prev, w.wire) {
			continue
		}
		h.Write(w.wire)
		prev = w.wire
	}
	return h.Sum(nil), nil
}

func compareLabels(la, lb [][]byte) int {
	i, j := len(la)-1, len(lb)-1
	for ; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	switch {
	case i >= 0:
		return 1
	case j >= 0:
		return -1
	}
	return 0
}

func ZoneSOA(rrs []dns.RR, origin string) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok && EqualNames(soa.Hdr.Name, origin) {
			return soa
		}
	}
	return nil
}

func VerifyZONEMD(rrs []dns.RR, origin string) error {
	soa := ZoneSOA(rrs, origin)
	if soa == nil {
		return ErrZONEMDNoSOA
	}
	var mds []*dns.ZONEMD
	for _, rr := range rrs {
		if md, ok := rr.(*dns.ZONEMD); ok && EqualNames(md.Hdr.Name, origin) {
			mds = append(mds, md)
		}
	}
	if len(mds) == 0 {
		return ErrZONEMDMissing
	}
	digests := make(map[uint8][]byte)
	sawUsable := false
	for _, md := range mds {
		if md.Scheme != zonemdSchemeSimple {
			continue
		}
		if md.Hash != zonemdHashSHA384 && md.Hash != zonemdHashSHA512 {
			continue
		}
		if md.Serial != soa.Serial {
			return ErrZONEMDSerial
		}
		sawUsable = true
		d, ok := digests[md.Hash]
		if !ok {
			var err error
			d, err = ZoneDigest(rrs, origin, md.Hash)
			if err != nil {
				return err
			}
			digests[md.Hash] = d
		}
		if strings.EqualFold(hex.EncodeToString(d), md.Digest) {
			return nil
		}
	}
	if !sawUsable {
		return ErrZONEMDUnsupported
	}
	return ErrZONEMDMismatch
}
