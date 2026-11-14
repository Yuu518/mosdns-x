package recursor

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
)

func edeFor(err error) uint16 {
	switch {
	case errors.Is(err, dnssec.ErrExpired):
		return dns.ExtendedErrorCodeSignatureExpired
	case errors.Is(err, dnssec.ErrNotYetValid):
		return dns.ExtendedErrorCodeSignatureNotYetValid
	case errors.Is(err, dnssec.ErrNoKey), errors.Is(err, dnssec.ErrDSMismatch):
		return dns.ExtendedErrorCodeDNSKEYMissing
	case errors.Is(err, dnssec.ErrNoSignature):
		return dns.ExtendedErrorCodeRRSIGsMissing
	}
	return dns.ExtendedErrorCodeDNSBogus
}

func signerOf(sigs []*dns.RRSIG) string {
	for _, s := range sigs {
		if dnssec.SupportedAlgorithm(s.Algorithm) {
			return s.SignerName
		}
	}
	if len(sigs) > 0 {
		return sigs[0].SignerName
	}
	return ""
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (r *Resolver) validateChain(ctx context.Context, st *reqState, ch *chainResult) (secStatus, uint16, error) {
	worst := secSecure
	var ede uint16
	var dnameSec secStatus
	var dname *rrset
	for _, s := range ch.sets {
		var sec secStatus
		var e uint16
		if s.synth && dname != nil {
			sec = dnameSec
		} else {
			var err error
			sec, e, err = r.validateSet(ctx, st, s)
			if err != nil {
				return 0, 0, err
			}
		}
		if s.rtype == dns.TypeDNAME {
			dname, dnameSec = s, sec
		}
		if sec > worst {
			worst, ede = sec, e
		}
		if worst == secBogus {
			return worst, ede, nil
		}
	}
	if ch.neg != nil {
		sec, e, err := r.validateNeg(ctx, st, ch.neg)
		if err != nil {
			return 0, 0, err
		}
		if sec > worst {
			worst, ede = sec, e
		}
	}
	return worst, ede, nil
}

func (r *Resolver) validateSet(ctx context.Context, st *reqState, s *rrset) (secStatus, uint16, error) {
	if sec, ede := s.status(); sec != secUnchecked {
		return sec, ede, nil
	}
	sec, ede, err := r.checkSet(ctx, st, s)
	if err != nil {
		return 0, 0, err
	}
	s.setStatus(sec, ede)
	return sec, ede, nil
}

func (r *Resolver) checkSet(ctx context.Context, st *reqState, s *rrset) (secStatus, uint16, error) {
	signer := signerOf(s.sigs)
	if signer == "" {
		zs, err := r.zoneSecFor(ctx, st, s.zone, s.name)
		if err != nil {
			return 0, 0, err
		}
		if zs.status == secSecure {
			return secBogus, dns.ExtendedErrorCodeRRSIGsMissing, nil
		}
		return zs.status, zs.ede, nil
	}
	if !dns.IsSubDomain(signer, s.name) {
		return secBogus, dns.ExtendedErrorCodeDNSBogus, nil
	}
	zs, err := r.zoneSec(ctx, st, signer)
	if err != nil {
		return 0, 0, err
	}
	if zs.status != secSecure {
		return zs.status, zs.ede, nil
	}
	if !dnssec.EqualNames(zs.zone, signer) {
		return secBogus, dns.ExtendedErrorCodeDNSBogus, nil
	}
	sig, err := dnssec.VerifyRRset(s.rrs, s.sigs, zs.keys, r.now(), st.vbudget)
	if err != nil {
		return secBogus, edeFor(err), nil
	}
	if int(sig.Labels) < dns.CountLabel(s.name) {
		nsecs, nsec3s := r.verifyProofs(st, s.proof, zs)
		switch dnssec.ProveWildcard(s.name, sig.Labels, nsecs, nsec3s) {
		case dnssec.NotProven:
			return secBogus, dns.ExtendedErrorCodeNSECMissing, nil
		case dnssec.ProvenInsecure:
			return secInsecure, 0, nil
		}
	}
	return secSecure, 0, nil
}

func (r *Resolver) verifyProofs(st *reqState, proofs []*rrset, zs *zoneSec) ([]*dns.NSEC, []*dns.NSEC3) {
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, p := range proofs {
		sec, _ := p.status()
		if sec == secUnchecked {
			sec = secBogus
			if dnssec.EqualNames(signerOf(p.sigs), zs.zone) {
				if _, err := dnssec.VerifyRRset(p.rrs, p.sigs, zs.keys, r.now(), st.vbudget); err == nil {
					sec = secSecure
				}
			}
			p.setStatus(sec, 0)
		}
		if sec != secSecure {
			continue
		}
		for _, rr := range p.rrs {
			switch x := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, x)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, x)
			}
		}
	}
	return nsecs, nsec3s
}

func secureNSECSets(proofs []*rrset) []*rrset {
	var out []*rrset
	for _, p := range proofs {
		if sec, _ := p.status(); sec == secSecure && p.rtype == dns.TypeNSEC {
			out = append(out, p)
		}
	}
	return out
}

func negSigner(n *negative) string {
	if n.soa != nil {
		if s := signerOf(n.soa.sigs); s != "" {
			return s
		}
	}
	for _, p := range n.proof {
		if s := signerOf(p.sigs); s != "" {
			return s
		}
	}
	return ""
}

func (r *Resolver) validateNeg(ctx context.Context, st *reqState, n *negative) (secStatus, uint16, error) {
	if sec, ede := n.status(); sec != secUnchecked {
		return sec, ede, nil
	}
	sec, ede, err := r.checkNeg(ctx, st, n)
	if err != nil {
		return 0, 0, err
	}
	n.setStatus(sec, ede)
	return sec, ede, nil
}

func (r *Resolver) checkNeg(ctx context.Context, st *reqState, n *negative) (secStatus, uint16, error) {
	signer := negSigner(n)
	if signer == "" {
		zs, err := r.zoneSecFor(ctx, st, n.zone, n.name)
		if err != nil {
			return 0, 0, err
		}
		if zs.status == secSecure {
			return secBogus, dns.ExtendedErrorCodeNSECMissing, nil
		}
		return zs.status, zs.ede, nil
	}
	if !dns.IsSubDomain(signer, n.name) {
		return secBogus, dns.ExtendedErrorCodeDNSBogus, nil
	}
	zs, err := r.zoneSec(ctx, st, signer)
	if err != nil {
		return 0, 0, err
	}
	if zs.status != secSecure {
		return zs.status, zs.ede, nil
	}
	if !dnssec.EqualNames(zs.zone, signer) {
		return secBogus, dns.ExtendedErrorCodeDNSBogus, nil
	}
	if n.soa != nil {
		if _, err := dnssec.VerifyRRset(n.soa.rrs, n.soa.sigs, zs.keys, r.now(), st.vbudget); err != nil {
			return secBogus, edeFor(err), nil
		}
	}
	nsecs, nsec3s := r.verifyProofs(st, n.proof, zs)
	var p dnssec.Proof
	if n.rcode == dns.RcodeNameError {
		p = dnssec.ProveNXDomain(n.name, nsecs, nsec3s)
	} else {
		p = dnssec.ProveNoData(n.name, n.qtype, nsecs, nsec3s)
	}
	switch p {
	case dnssec.Proven:
		if len(nsecs) > 0 && n.soa != nil {
			r.cache.addNSECs(zs.zone, n.soa, secureNSECSets(n.proof))
		}
		return secSecure, 0, nil
	case dnssec.ProvenInsecure:
		return secInsecure, 0, nil
	}
	return secBogus, dns.ExtendedErrorCodeNSECMissing, nil
}

func (r *Resolver) zoneSecFor(ctx context.Context, st *reqState, start, owner string) (*zoneSec, error) {
	if start == "" || !dns.IsSubDomain(start, owner) {
		start = "."
	}
	zs, err := r.zoneSec(ctx, st, start)
	if err != nil || zs.status != secSecure {
		return zs, err
	}
	var names []string
	for n := owner; dnssec.IsStrictSubDomain(start, n); n = dnssec.ParentName(n) {
		names = append(names, n)
	}
	for i := len(names) - 1; i >= 0; i-- {
		z, err := r.zoneSec(ctx, st, names[i])
		if err != nil {
			return nil, err
		}
		if z.status != secSecure {
			return z, nil
		}
		zs = z
	}
	return zs, nil
}

func (r *Resolver) insecureAncestor(zone string) *zoneSec {
	for p := dnssec.ParentName(zone); ; p = dnssec.ParentName(p) {
		if z := r.cache.getKeys(p); z != nil && z.status == secInsecure && dnssec.EqualNames(z.zone, p) {
			return z
		}
		if p == "." {
			return nil
		}
	}
}

func (r *Resolver) zoneSec(ctx context.Context, st *reqState, zone string) (*zoneSec, error) {
	zone = dns.CanonicalName(zone)
	if z := r.cache.getKeys(zone); z != nil {
		return z, nil
	}
	if zone != "." {
		if z := r.insecureAncestor(zone); z != nil {
			return z, nil
		}
	}
	var zs *zoneSec
	var err error
	if zone == "." {
		zs, err = r.rootSec(ctx, st)
	} else {
		zs, err = r.childSec(ctx, st, zone)
	}
	if err != nil {
		return nil, err
	}
	if zs.status == secBogus {
		st.addBogusZone(zone)
		zs.expire = minTime(zs.expire, r.now().Add(bogusTTL))
	}
	if zs.expire.IsZero() {
		zs.expire = r.now().Add(bogusTTL)
	}
	r.cache.putKeys(zone, zs)
	return zs, nil
}

func bogusZone(zone string, ede uint16) *zoneSec {
	return &zoneSec{zone: zone, status: secBogus, ede: ede}
}

func dnskeysOf(s *rrset) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range s.rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, k)
		}
	}
	return out
}

func (r *Resolver) prefetchKey(ctx context.Context, st *reqState, zone string) {
	if r.cache.getSet(zone, dns.TypeDNSKEY, trustAnswer) != nil || r.cache.getKeys(zone) != nil {
		return
	}
	st.mu.Lock()
	if _, ok := st.keyFetch[zone]; ok {
		st.mu.Unlock()
		return
	}
	done := make(chan struct{})
	st.keyFetch[zone] = done
	st.mu.Unlock()
	c := st.fork()
	c.noWait = true
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer close(done)
		defer r.recoverPanic(nil)
		r.lookup(ctx, c, zone, dns.TypeDNSKEY, false)
	}()
}

func (r *Resolver) waitKeyFetch(ctx context.Context, st *reqState, zone string) {
	if st.noWait {
		return
	}
	st.mu.Lock()
	done := st.keyFetch[zone]
	st.mu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (r *Resolver) fetchKeys(ctx context.Context, st *reqState, zone string, ds []*dns.DS, expire time.Time) (*zoneSec, error) {
	r.waitKeyFetch(ctx, st, zone)
	kr, err := r.lookup(ctx, st, zone, dns.TypeDNSKEY, false)
	if err != nil {
		return nil, err
	}
	if kr.neg != nil {
		st.addBogusServer(kr.neg.server)
		return bogusZone(zone, dns.ExtendedErrorCodeDNSKEYMissing), nil
	}
	ks := findSet(kr.sets, zone, dns.TypeDNSKEY)
	if ks == nil {
		return bogusZone(zone, dns.ExtendedErrorCodeDNSKEYMissing), nil
	}
	keys := dnskeysOf(ks)
	now := r.now()
	err = dnssec.VerifyDNSKEYs(keys, ks.sigs, ds, now, st.vbudget)
	if errors.Is(err, dnssec.ErrUnsupported) {
		return &zoneSec{zone: zone, status: secInsecure, expire: minTime(expire, ks.expire)}, nil
	}
	if err != nil {
		ks.setStatus(secBogus, edeFor(err))
		r.cache.delSet(zone, dns.TypeDNSKEY)
		st.addBogusServer(ks.server)
		return bogusZone(zone, edeFor(err)), nil
	}
	ks.setStatus(secSecure, 0)
	if zone == "." && r.auto != nil {
		r.auto.update(keys, ks.sigs, now)
	}
	return &zoneSec{zone: zone, status: secSecure, keys: keys, expire: minTime(expire, ks.expire)}, nil
}

func (r *Resolver) trustAnchors() []*dns.DS {
	if r.auto != nil {
		return r.auto.anchors()
	}
	return r.anchors
}

func (r *Resolver) rootSec(ctx context.Context, st *reqState) (*zoneSec, error) {
	return r.fetchKeys(ctx, st, ".", r.trustAnchors(), r.now().Add(maxCacheTTL))
}

func inherit(ps *zoneSec, expire time.Time) *zoneSec {
	return &zoneSec{zone: ps.zone, status: ps.status, keys: ps.keys, ede: ps.ede, expire: minTime(ps.expire, expire)}
}

func (r *Resolver) cutAbove(zone string) string {
	for p := dnssec.ParentName(zone); p != "."; p = dnssec.ParentName(p) {
		if r.cache.getSet(p, dns.TypeNS, trustAuthority) != nil {
			return p
		}
	}
	return "."
}

func (r *Resolver) childSec(ctx context.Context, st *reqState, zone string) (*zoneSec, error) {
	ps, err := r.zoneSec(ctx, st, r.cutAbove(zone))
	if err != nil {
		return nil, err
	}
	if ps.status != secSecure {
		return inherit(ps, ps.expire), nil
	}
	res, err := r.lookup(ctx, st, zone, dns.TypeDS, false)
	if err != nil {
		return nil, err
	}
	if n := res.neg; n != nil {
		signer := negSigner(n)
		parent := signer
		if parent == "" {
			parent = n.zone
		}
		if !dnssec.IsStrictSubDomain(parent, zone) {
			return bogusZone(zone, dns.ExtendedErrorCodeDNSBogus), nil
		}
		ps, err := r.zoneSec(ctx, st, parent)
		if err != nil {
			return nil, err
		}
		if ps.status != secSecure {
			return inherit(ps, n.expire), nil
		}
		if signer == "" {
			return bogusZone(zone, dns.ExtendedErrorCodeNSECMissing), nil
		}
		if !dnssec.EqualNames(ps.zone, signer) {
			return bogusZone(zone, dns.ExtendedErrorCodeDNSBogus), nil
		}
		nsecs, nsec3s := r.verifyProofs(st, n.proof, ps)
		var p dnssec.Proof
		deleg := false
		if n.rcode == dns.RcodeNameError {
			p = dnssec.ProveNXDomain(zone, nsecs, nsec3s)
		} else {
			p, deleg = dnssec.ProveNoDS(zone, nsecs, nsec3s)
		}
		switch {
		case p == dnssec.NotProven:
			r.cache.delNeg(n)
			st.addBogusServer(n.server)
			return bogusZone(zone, dns.ExtendedErrorCodeNSECMissing), nil
		case p == dnssec.ProvenInsecure, deleg:
			return &zoneSec{zone: zone, status: secInsecure, expire: minTime(ps.expire, n.expire)}, nil
		}
		return inherit(ps, n.expire), nil
	}
	ds := findSet(res.sets, zone, dns.TypeDS)
	if ds == nil {
		return bogusZone(zone, dns.ExtendedErrorCodeDNSBogus), nil
	}
	signer := signerOf(ds.sigs)
	parent := signer
	if parent == "" {
		parent = ds.zone
	}
	if !dnssec.IsStrictSubDomain(parent, zone) {
		return bogusZone(zone, dns.ExtendedErrorCodeDNSBogus), nil
	}
	ps, err = r.zoneSec(ctx, st, parent)
	if err != nil {
		return nil, err
	}
	if ps.status != secSecure {
		return inherit(ps, ds.expire), nil
	}
	if signer == "" {
		return bogusZone(zone, dns.ExtendedErrorCodeRRSIGsMissing), nil
	}
	if !dnssec.EqualNames(ps.zone, signer) {
		return bogusZone(zone, dns.ExtendedErrorCodeDNSBogus), nil
	}
	if sec, ede := ds.status(); sec == secBogus {
		return bogusZone(zone, ede), nil
	} else if sec != secSecure {
		if _, err := dnssec.VerifyRRset(ds.rrs, ds.sigs, ps.keys, r.now(), st.vbudget); err != nil {
			ds.setStatus(secBogus, edeFor(err))
			r.cache.delSet(zone, dns.TypeDS)
			st.addBogusServer(ds.server)
			return bogusZone(zone, edeFor(err)), nil
		}
		ds.setStatus(secSecure, 0)
	}
	var dsList []*dns.DS
	for _, rr := range ds.rrs {
		if d, ok := rr.(*dns.DS); ok {
			dsList = append(dsList, d)
		}
	}
	if !dnssec.HasSupportedDS(dsList) {
		return &zoneSec{zone: zone, status: secInsecure, expire: minTime(ps.expire, ds.expire)}, nil
	}
	return r.fetchKeys(ctx, st, zone, dsList, minTime(ps.expire, ds.expire))
}
