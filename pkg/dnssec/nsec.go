package dnssec

import (
	"github.com/miekg/dns"
)

type Proof uint8

const (
	NotProven Proof = iota
	Proven
	ProvenInsecure
)

func (p Proof) String() string {
	switch p {
	case Proven:
		return "proven"
	case ProvenInsecure:
		return "proven_insecure"
	}
	return "not_proven"
}

func nsecCovers(n *dns.NSEC, name string) bool {
	owner, next := n.Hdr.Name, n.NextDomain
	if CompareNames(owner, name) >= 0 {
		return false
	}
	if CompareNames(owner, next) < 0 {
		return CompareNames(name, next) < 0
	}
	return dns.IsSubDomain(next, name)
}

func nsecIsAncestorCut(n *dns.NSEC, name string) bool {
	if !IsStrictSubDomain(n.Hdr.Name, name) {
		return false
	}
	return isDelegationBitmap(n.TypeBitMap) || typeInBitmap(n.TypeBitMap, dns.TypeDNAME)
}

func nsecMatch(nsecs []*dns.NSEC, name string) *dns.NSEC {
	for _, n := range nsecs {
		if EqualNames(n.Hdr.Name, name) {
			return n
		}
	}
	return nil
}

func nsecCover(nsecs []*dns.NSEC, name string) *dns.NSEC {
	for _, n := range nsecs {
		if nsecCovers(n, name) && !nsecIsAncestorCut(n, name) {
			return n
		}
	}
	return nil
}

func nsecEmptyNonTerminal(nsecs []*dns.NSEC, name string) bool {
	for _, n := range nsecs {
		if CompareNames(n.Hdr.Name, name) < 0 && IsStrictSubDomain(name, n.NextDomain) {
			return true
		}
	}
	return false
}

func nsecClosestEncloser(n *dns.NSEC, name string) string {
	a := CommonAncestor(name, n.Hdr.Name)
	b := CommonAncestor(name, n.NextDomain)
	if dns.CountLabel(b) > dns.CountLabel(a) {
		return b
	}
	return a
}

func wildcardOf(name string) string {
	if name == "." {
		return "*."
	}
	return "*." + name
}

func nsecNoData(n *dns.NSEC, qtype uint16, name string) bool {
	bm := n.TypeBitMap
	if typeInBitmap(bm, qtype) || typeInBitmap(bm, dns.TypeCNAME) {
		return false
	}
	if qtype == dns.TypeDS {
		return !typeInBitmap(bm, dns.TypeSOA) || name == "."
	}
	return !isDelegationBitmap(bm)
}

func ProveNXDomain(name string, nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) Proof {
	if len(nsecs) > 0 {
		if nsecMatch(nsecs, name) != nil {
			return NotProven
		}
		c := nsecCover(nsecs, name)
		if c == nil {
			return NotProven
		}
		ce := nsecClosestEncloser(c, name)
		if nsecCover(nsecs, wildcardOf(ce)) == nil {
			return NotProven
		}
		return Proven
	}
	if len(nsec3s) > 0 {
		s := newNSEC3Set(nsec3s)
		if s == nil {
			return NotProven
		}
		if s.insecure {
			return ProvenInsecure
		}
		ce, _, ncRR, ok := s.closestEncloser(name)
		if !ok || ce == name {
			return NotProven
		}
		h, ok := s.hash(wildcardOf(ce))
		if !ok || s.coverHash(h) == nil {
			return NotProven
		}
		if ncRR.Flags&1 != 0 {
			return ProvenInsecure
		}
		return Proven
	}
	return NotProven
}

func ProveNoData(name string, qtype uint16, nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) Proof {
	if len(nsecs) > 0 {
		if m := nsecMatch(nsecs, name); m != nil {
			if nsecNoData(m, qtype, name) {
				return Proven
			}
			return NotProven
		}
		if nsecEmptyNonTerminal(nsecs, name) {
			return Proven
		}
		c := nsecCover(nsecs, name)
		if c == nil {
			return NotProven
		}
		ce := nsecClosestEncloser(c, name)
		if w := nsecMatch(nsecs, wildcardOf(ce)); w != nil && nsecNoData(w, qtype, name) {
			return Proven
		}
		return NotProven
	}
	if len(nsec3s) > 0 {
		s := newNSEC3Set(nsec3s)
		if s == nil {
			return NotProven
		}
		if s.insecure {
			return ProvenInsecure
		}
		h, ok := s.hash(name)
		if !ok {
			return NotProven
		}
		if m := s.matchHash(h); m != nil {
			if nsec3NoData(m, qtype, name) {
				return Proven
			}
			return NotProven
		}
		ce, _, ncRR, ok := s.closestEncloser(name)
		if !ok {
			return NotProven
		}
		if qtype == dns.TypeDS && ncRR.Flags&1 != 0 {
			return ProvenInsecure
		}
		wh, ok := s.hash(wildcardOf(ce))
		if !ok {
			return NotProven
		}
		if w := s.matchHash(wh); w != nil && nsec3NoData(w, qtype, name) {
			return Proven
		}
		return NotProven
	}
	return NotProven
}

func ProveWildcard(name string, sigLabels uint8, nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) Proof {
	if int(sigLabels) >= dns.CountLabel(name) {
		return Proven
	}
	if len(nsecs) > 0 {
		if nsecCover(nsecs, name) != nil {
			return Proven
		}
		return NotProven
	}
	if len(nsec3s) > 0 {
		s := newNSEC3Set(nsec3s)
		if s == nil {
			return NotProven
		}
		if s.insecure {
			return ProvenInsecure
		}
		idx := dns.Split(name)
		ce := name[idx[len(idx)-int(sigLabels)]:]
		if sigLabels == 0 {
			ce = "."
		}
		nc := NextCloser(name, ce)
		h, ok := s.hash(nc)
		if !ok || s.coverHash(h) == nil {
			return NotProven
		}
		return Proven
	}
	return NotProven
}

func SynthesizeDenial(name string, qtype uint16, prev func(string) *dns.NSEC) (int, []*dns.NSEC, bool) {
	n := prev(name)
	if n == nil {
		return 0, nil, false
	}
	set := []*dns.NSEC{n}
	if EqualNames(n.Hdr.Name, name) || nsecEmptyNonTerminal(set, name) {
		if ProveNoData(name, qtype, set, nil) == Proven {
			return dns.RcodeSuccess, set, true
		}
		return 0, nil, false
	}
	if !nsecCovers(n, name) || nsecIsAncestorCut(n, name) {
		return 0, nil, false
	}
	w := prev(wildcardOf(nsecClosestEncloser(n, name)))
	if w == nil {
		return 0, nil, false
	}
	if w != n {
		set = append(set, w)
	}
	if ProveNXDomain(name, set, nil) == Proven {
		return dns.RcodeNameError, set, true
	}
	return 0, nil, false
}

func ProveNoDS(name string, nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) (p Proof, delegation bool) {
	if len(nsecs) > 0 {
		if m := nsecMatch(nsecs, name); m != nil {
			bm := m.TypeBitMap
			if typeInBitmap(bm, dns.TypeDS) || (typeInBitmap(bm, dns.TypeSOA) && name != ".") {
				return NotProven, false
			}
			return Proven, typeInBitmap(bm, dns.TypeNS)
		}
		if nsecEmptyNonTerminal(nsecs, name) {
			return Proven, false
		}
		if nsecCover(nsecs, name) != nil {
			return Proven, false
		}
		return NotProven, false
	}
	if len(nsec3s) > 0 {
		s := newNSEC3Set(nsec3s)
		if s == nil {
			return NotProven, false
		}
		if s.insecure {
			return ProvenInsecure, true
		}
		h, ok := s.hash(name)
		if !ok {
			return NotProven, false
		}
		if m := s.matchHash(h); m != nil {
			bm := m.TypeBitMap
			if typeInBitmap(bm, dns.TypeDS) || (typeInBitmap(bm, dns.TypeSOA) && name != ".") {
				return NotProven, false
			}
			return Proven, typeInBitmap(bm, dns.TypeNS)
		}
		_, _, ncRR, ok := s.closestEncloser(name)
		if !ok {
			return NotProven, false
		}
		if ncRR.Flags&1 != 0 {
			return ProvenInsecure, true
		}
		return Proven, false
	}
	return NotProven, false
}
