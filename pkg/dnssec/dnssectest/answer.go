package dnssectest

import (
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
)

func (z *Zone) Answer(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Authoritative = true
	do := false
	if opt := q.IsEdns0(); opt != nil {
		do = opt.Do()
		r.SetEdns0(1232, do)
	}
	if len(q.Question) != 1 {
		r.Rcode = dns.RcodeFormatError
		return r
	}
	qname := dns.CanonicalName(q.Question[0].Name)
	qtype := q.Question[0].Qtype
	if !dns.IsSubDomain(z.Origin, qname) {
		r.Rcode = dns.RcodeRefused
		r.Authoritative = false
		return r
	}
	if cut := z.cutFor(qname, qtype); cut != "" {
		z.referral(r, cut, do)
		return r
	}
	if owner, dname := z.dnameAbove(qname); dname != nil {
		z.addSet(&r.Answer, owner, dns.TypeDNAME, do)
		target := strings.TrimSuffix(qname, owner) + dname.Target
		if dname.Target == "." {
			target = strings.TrimSuffix(qname, owner)
		}
		r.Answer = append(r.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: dname.Hdr.Ttl},
			Target: dns.Fqdn(target),
		})
		return r
	}
	if _, ok := z.data[qname]; ok {
		switch {
		case len(z.data[qname][qtype]) > 0:
			z.addSet(&r.Answer, qname, qtype, do)
		case len(z.data[qname][dns.TypeCNAME]) > 0:
			z.addSet(&r.Answer, qname, dns.TypeCNAME, do)
		default:
			z.noData(r, qname, do)
		}
		return r
	}
	if z.isENT(qname) {
		z.noData(r, qname, do)
		return r
	}
	ce := z.closestEncloser(qname)
	wc := "*." + ce
	if ce == "." {
		wc = "*."
	}
	if wm, ok := z.data[wc]; ok {
		t := qtype
		if len(wm[t]) == 0 && len(wm[dns.TypeCNAME]) > 0 {
			t = dns.TypeCNAME
		}
		if len(wm[t]) > 0 {
			for _, rr := range wm[t] {
				c := dns.Copy(rr)
				c.Header().Name = qname
				r.Answer = append(r.Answer, c)
			}
			if do && z.Signed() {
				for _, s := range z.sigs[wc][t] {
					c := dns.Copy(s).(*dns.RRSIG)
					c.Hdr.Name = qname
					r.Answer = append(r.Answer, c)
				}
				z.addDenialCover(&r.Ns, qname, ce)
			}
			return r
		}
		z.addSOA(&r.Ns, do)
		if do && z.Signed() {
			if z.Denial != DenialNSEC {
				z.addNSEC3Match(&r.Ns, ce)
			}
			z.addDenialCover(&r.Ns, qname, ce)
			z.addDenialMatch(&r.Ns, wc)
		}
		return r
	}
	r.Rcode = dns.RcodeNameError
	z.addSOA(&r.Ns, do)
	if do && z.Signed() {
		z.addDenialCover(&r.Ns, qname, ce)
		if z.Denial == DenialNSEC {
			z.addNSECCover(&r.Ns, wc)
		} else {
			z.addNSEC3Match(&r.Ns, ce)
			z.addNSEC3Cover(&r.Ns, wc)
		}
	}
	return r
}

func (z *Zone) cutFor(qname string, qtype uint16) string {
	var labels []string
	for n := qname; n != z.Origin && dns.IsSubDomain(z.Origin, n); n = dnssec.ParentName(n) {
		labels = append(labels, n)
	}
	for i := len(labels) - 1; i >= 0; i-- {
		n := labels[i]
		if z.isCut(n) {
			if n == qname && qtype == dns.TypeDS {
				return ""
			}
			return n
		}
	}
	return ""
}

func (z *Zone) dnameAbove(qname string) (string, *dns.DNAME) {
	for n := dnssec.ParentName(qname); dns.IsSubDomain(z.Origin, n); n = dnssec.ParentName(n) {
		if rrs := z.data[n][dns.TypeDNAME]; len(rrs) > 0 {
			return n, rrs[0].(*dns.DNAME)
		}
		if n == z.Origin {
			break
		}
	}
	return "", nil
}

func (z *Zone) isENT(name string) bool {
	for n := range z.data {
		if dnssec.IsStrictSubDomain(name, n) && !z.isGlue(n) {
			return true
		}
	}
	return false
}

func (z *Zone) closestEncloser(name string) string {
	for n := dnssec.ParentName(name); ; n = dnssec.ParentName(n) {
		if _, ok := z.data[n]; ok || z.isENT(n) {
			return n
		}
		if n == z.Origin || n == "." {
			return z.Origin
		}
	}
}

func (z *Zone) addSet(dst *[]dns.RR, name string, t uint16, do bool) {
	*dst = append(*dst, z.data[name][t]...)
	if do {
		for _, s := range z.sigs[name][t] {
			*dst = append(*dst, s)
		}
	}
}

func (z *Zone) addSOA(dst *[]dns.RR, do bool) {
	z.addSet(dst, z.Origin, dns.TypeSOA, do)
}

func (z *Zone) noData(r *dns.Msg, name string, do bool) {
	z.addSOA(&r.Ns, do)
	if !do || !z.Signed() {
		return
	}
	if z.Denial == DenialNSEC {
		if len(z.data[name][dns.TypeNSEC]) > 0 {
			z.addSet(&r.Ns, name, dns.TypeNSEC, true)
			return
		}
		z.addNSECCover(&r.Ns, name)
		return
	}
	if !z.addNSEC3Match(&r.Ns, name) {
		ce := z.closestEncloser(name)
		z.addNSEC3Match(&r.Ns, ce)
		z.addNSEC3Cover(&r.Ns, dnssec.NextCloser(name, ce))
	}
}

func (z *Zone) referral(r *dns.Msg, cut string, do bool) {
	r.Authoritative = false
	z.addSet(&r.Ns, cut, dns.TypeNS, false)
	if do && z.Signed() {
		if len(z.data[cut][dns.TypeDS]) > 0 {
			z.addSet(&r.Ns, cut, dns.TypeDS, true)
		} else if z.Denial == DenialNSEC {
			z.addSet(&r.Ns, cut, dns.TypeNSEC, true)
		} else if !z.addNSEC3Match(&r.Ns, cut) {
			ce := z.closestEncloser(cut)
			z.addNSEC3Match(&r.Ns, ce)
			z.addNSEC3Cover(&r.Ns, dnssec.NextCloser(cut, ce))
		}
	}
	for _, rr := range z.data[cut][dns.TypeNS] {
		host := dns.CanonicalName(rr.(*dns.NS).Ns)
		if !dns.IsSubDomain(z.Origin, host) {
			continue
		}
		r.Extra = append(r.Extra, z.data[host][dns.TypeA]...)
		r.Extra = append(r.Extra, z.data[host][dns.TypeAAAA]...)
	}
}

func (z *Zone) addDenialCover(dst *[]dns.RR, qname, ce string) {
	if z.Denial == DenialNSEC {
		z.addNSECCover(dst, qname)
		return
	}
	z.addNSEC3Cover(dst, dnssec.NextCloser(qname, ce))
}

func (z *Zone) addDenialMatch(dst *[]dns.RR, name string) {
	if z.Denial == DenialNSEC {
		z.addSet(dst, name, dns.TypeNSEC, true)
		return
	}
	z.addNSEC3Match(dst, name)
}

func appendUnique(dst *[]dns.RR, rrs ...dns.RR) {
	for _, rr := range rrs {
		dup := false
		for _, x := range *dst {
			if x == rr {
				dup = true
				break
			}
		}
		if !dup {
			*dst = append(*dst, rr)
		}
	}
}

func (z *Zone) addNSECCover(dst *[]dns.RR, name string) {
	if len(z.nsecs) == 0 {
		return
	}
	idx := sort.Search(len(z.nsecs), func(i int) bool {
		return dnssec.CompareNames(z.nsecs[i].Hdr.Name, name) > 0
	}) - 1
	if idx < 0 {
		idx = len(z.nsecs) - 1
	}
	n := z.nsecs[idx]
	appendUnique(dst, n)
	for _, s := range z.sigs[n.Hdr.Name][dns.TypeNSEC] {
		appendUnique(dst, s)
	}
}

func (z *Zone) nsec3Hash(name string) string {
	return dns.HashName(name, dns.SHA1, z.Iterations, z.Salt)
}

func (z *Zone) addNSEC3(dst *[]dns.RR, n *dns.NSEC3) {
	appendUnique(dst, n)
	for _, s := range z.sigs[n.Hdr.Name][dns.TypeNSEC3] {
		appendUnique(dst, s)
	}
}

func (z *Zone) addNSEC3Match(dst *[]dns.RR, name string) bool {
	h := z.nsec3Hash(name)
	for _, n := range z.nsec3s {
		if strings.EqualFold(strings.SplitN(n.Hdr.Name, ".", 2)[0], h) {
			z.addNSEC3(dst, n)
			return true
		}
	}
	return false
}

func (z *Zone) addNSEC3Cover(dst *[]dns.RR, name string) {
	if len(z.nsec3s) == 0 {
		return
	}
	h := z.nsec3Hash(name)
	idx := sort.Search(len(z.nsec3s), func(i int) bool {
		return strings.ToUpper(strings.SplitN(z.nsec3s[i].Hdr.Name, ".", 2)[0]) > h
	}) - 1
	if idx < 0 {
		idx = len(z.nsec3s) - 1
	}
	z.addNSEC3(dst, z.nsec3s[idx])
}
