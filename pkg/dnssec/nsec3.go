package dnssec

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	MaxNSEC3Iterations = 100
	maxNSEC3Hashes     = 64
)

type nsec3Set struct {
	recs     []*dns.NSEC3
	zone     string
	alg      uint8
	iter     uint16
	salt     string
	insecure bool
	hashes   map[string]string
	left     int
}

func nsec3Zone(n *dns.NSEC3) string {
	return ParentName(n.Hdr.Name)
}

func nsec3OwnerHash(n *dns.NSEC3) string {
	off, _ := dns.NextLabel(n.Hdr.Name, 0)
	if off == 0 {
		return ""
	}
	return strings.ToUpper(n.Hdr.Name[:off-1])
}

func newNSEC3Set(recs []*dns.NSEC3) *nsec3Set {
	if len(recs) == 0 {
		return nil
	}
	first := recs[0]
	s := &nsec3Set{
		zone:   nsec3Zone(first),
		alg:    first.Hash,
		iter:   first.Iterations,
		salt:   strings.ToUpper(first.Salt),
		hashes: make(map[string]string),
		left:   maxNSEC3Hashes,
	}
	for _, n := range recs {
		if n.Hash != s.alg || n.Iterations != s.iter || !strings.EqualFold(n.Salt, s.salt) || !EqualNames(nsec3Zone(n), s.zone) {
			continue
		}
		s.recs = append(s.recs, n)
	}
	if s.alg != dns.SHA1 || s.iter > MaxNSEC3Iterations {
		s.insecure = true
	}
	return s
}

func (s *nsec3Set) hash(name string) (string, bool) {
	name = dns.CanonicalName(name)
	if h, ok := s.hashes[name]; ok {
		return h, true
	}
	if s.left <= 0 {
		return "", false
	}
	s.left--
	salt := s.salt
	if salt == "-" {
		salt = ""
	}
	h := dns.HashName(name, s.alg, s.iter, salt)
	if h == "" {
		return "", false
	}
	s.hashes[name] = h
	return h, true
}

func (s *nsec3Set) matchHash(h string) *dns.NSEC3 {
	for _, n := range s.recs {
		if nsec3OwnerHash(n) == h {
			return n
		}
	}
	return nil
}

func (s *nsec3Set) coverHash(h string) *dns.NSEC3 {
	for _, n := range s.recs {
		o := nsec3OwnerHash(n)
		next := strings.ToUpper(n.NextDomain)
		switch {
		case o == next:
			if h != o {
				return n
			}
		case o < next:
			if o < h && h < next {
				return n
			}
		default:
			if h > o || h < next {
				return n
			}
		}
	}
	return nil
}

func (s *nsec3Set) closestEncloser(name string) (ce, nc string, ncRR *dns.NSEC3, ok bool) {
	if !dns.IsSubDomain(s.zone, name) {
		return "", "", nil, false
	}
	next := ""
	cur := name
	for {
		h, hok := s.hash(cur)
		if !hok {
			return "", "", nil, false
		}
		if s.matchHash(h) != nil {
			if next == "" {
				return cur, "", nil, false
			}
			nh, nok := s.hash(next)
			if !nok {
				return "", "", nil, false
			}
			rr := s.coverHash(nh)
			if rr == nil {
				return "", "", nil, false
			}
			return cur, next, rr, true
		}
		if EqualNames(cur, s.zone) {
			return "", "", nil, false
		}
		next = cur
		cur = ParentName(cur)
	}
}

func nsec3NoData(n *dns.NSEC3, qtype uint16, name string) bool {
	bm := n.TypeBitMap
	if typeInBitmap(bm, qtype) || typeInBitmap(bm, dns.TypeCNAME) {
		return false
	}
	if qtype == dns.TypeDS {
		return !typeInBitmap(bm, dns.TypeSOA) || name == "."
	}
	return !isDelegationBitmap(bm)
}
