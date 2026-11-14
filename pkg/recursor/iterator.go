package recursor

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

type chainResult struct {
	sets []*rrset
	neg  *negative
}

type lookupResult struct {
	sets []*rrset
	neg  *negative
}

type respKind uint8

const (
	kindFail respKind = iota
	kindLame
	kindAnswer
	kindNoData
	kindNXDomain
	kindReferral
)

type serverResponse struct {
	msg     *dns.Msg
	kind    respKind
	child   string
	from    netip.Addr
	sentECS bool
	scope   uint8
}

func (r *Resolver) resolveChain(ctx context.Context, st *reqState, name string, qtype uint16, withECS bool) (*chainResult, error) {
	ch := &chainResult{}
	cur := name
	seen := map[string]bool{cur: true}
	for i := 0; ; i++ {
		if i > maxCNAMEChain {
			return nil, errCNAMEChain
		}
		res, err := r.lookup(ctx, st, cur, qtype, withECS)
		if err != nil {
			return nil, err
		}
		if res.neg != nil {
			ch.neg = res.neg
			return ch, nil
		}
		next := ""
		final := false
		for _, s := range res.sets {
			ch.sets = append(ch.sets, s)
			switch {
			case s.rtype == qtype:
				final = true
			case s.rtype == dns.TypeCNAME && len(s.rrs) > 0:
				next = dns.CanonicalName(s.rrs[0].(*dns.CNAME).Target)
			}
		}
		if final || next == "" {
			return ch, nil
		}
		if seen[next] {
			return nil, errCNAMEChain
		}
		seen[next] = true
		cur = next
	}
}

func (r *Resolver) lookup(ctx context.Context, st *reqState, name string, qtype uint16, withECS bool) (*lookupResult, error) {
	key := setKey(name, qtype)
	if st.stack[key] {
		return nil, errLoop
	}
	st.stack[key] = true
	defer delete(st.stack, key)

	useECS := withECS && st.ecs != nil
	if res := r.fromCache(name, qtype, useECS); res != nil {
		r.cacheHits.Add(1)
		if withECS && r.opts.Prefetch {
			r.maybePrefetch(res, name, qtype, st.ecs)
		}
		return res, nil
	}
	if st.validate {
		if n := r.belowNXDomain(name, qtype); n != nil {
			r.synth.Add(1)
			return &lookupResult{neg: n}, nil
		}
		if n := r.synthNegative(name, qtype); n != nil {
			r.synth.Add(1)
			return &lookupResult{neg: n}, nil
		}
	}
	return r.iterate(ctx, st, name, qtype, useECS)
}

func deriveNX(n *negative, name string, qtype uint16) *negative {
	d := &negative{
		name:     name,
		qtype:    qtype,
		rcode:    dns.RcodeNameError,
		soa:      n.soa,
		proof:    n.proof,
		expire:   n.expire,
		prefetch: n.expire,
		zone:     n.zone,
		server:   n.server,
		ecsOK:    true,
	}
	d.setStatus(secSecure, 0)
	return d
}

func (r *Resolver) belowNXDomain(name string, qtype uint16) *negative {
	for p := name; p != "."; {
		p = dnssec.ParentName(p)
		n := r.cache.getNX(p)
		if n == nil || n.rcode != dns.RcodeNameError {
			continue
		}
		if sec, _ := n.status(); sec == secSecure {
			return deriveNX(n, name, qtype)
		}
	}
	return nil
}

func (r *Resolver) synthNegative(name string, qtype uint16) *negative {
	start := name
	if qtype == dns.TypeDS && name != "." {
		start = dnssec.ParentName(name)
	}
	z := r.cache.nsecZoneFor(start)
	if z == nil {
		return nil
	}
	now := r.now()
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.soa == nil || !now.Before(z.soa.expire) {
		return nil
	}
	used := make(map[*dns.NSEC]*rrset)
	prev := func(n string) *dns.NSEC {
		e := z.prev(n, now)
		if e == nil {
			return nil
		}
		used[e.nsec] = e.set
		return e.nsec
	}
	rcode, nsecs, ok := dnssec.SynthesizeDenial(name, qtype, prev)
	if !ok {
		return nil
	}
	n := &negative{
		name:   name,
		qtype:  qtype,
		rcode:  rcode,
		soa:    z.soa,
		expire: z.soa.expire,
		zone:   z.zone,
		ecsOK:  true,
	}
	for _, x := range nsecs {
		s := used[x]
		n.proof = append(n.proof, s)
		n.expire = minTime(n.expire, s.expire)
	}
	n.prefetch = n.expire
	n.setStatus(secSecure, 0)
	return n
}

func (r *Resolver) fromCache(name string, qtype uint16, useECS bool) *lookupResult {
	ok := func(ecsOK bool) bool { return !useECS || ecsOK }
	if n := r.cache.getNeg(name, qtype); n != nil && ok(n.ecsOK) {
		return &lookupResult{neg: n}
	}
	if s := r.cache.getSet(name, qtype, trustAnswer); s != nil && ok(s.ecsOK) {
		return &lookupResult{sets: []*rrset{s}}
	}
	if qtype != dns.TypeCNAME {
		if s := r.cache.getSet(name, dns.TypeCNAME, trustAnswer); s != nil && ok(s.ecsOK) {
			return &lookupResult{sets: []*rrset{s}}
		}
	}
	return nil
}

func (r *Resolver) findCut(ctx context.Context, name string, qtype uint16) (string, *rrset) {
	n := name
	if qtype == dns.TypeDS && n != "." {
		n = dnssec.ParentName(n)
	}
	for {
		if n == "." {
			return ".", r.rootNS(ctx)
		}
		if s := r.cache.getSet(n, dns.TypeNS, trustAuthority); s != nil {
			return n, s
		}
		n = dnssec.ParentName(n)
	}
}

func minimizedName(name, known string, steps int) (string, bool) {
	total := dns.CountLabel(name)
	diff := total - dns.CountLabel(known)
	if diff <= 1 || steps >= maxMinimizeSteps {
		return "", false
	}
	count := steps + 1
	if total > maxMinimizeSteps && count > minimiseOneLab {
		multi := total - 1 - minimiseOneLab
		multiSteps := maxMinimizeSteps - minimiseOneLab
		extra := multi / multiSteps
		if maxMinimizeSteps-count >= multi%multiSteps {
			extra--
		}
		if extra < diff {
			diff -= extra
		} else {
			diff = 1
		}
	}
	if diff <= 1 {
		return "", false
	}
	return name[dns.Split(name)[diff-1]:], true
}

func (r *Resolver) iterate(ctx context.Context, st *reqState, name string, qtype uint16, useECS bool) (*lookupResult, error) {
	zone, ns := r.findCut(ctx, name, qtype)
	known := zone
	minimize := !r.opts.DisableQNameMin
	minSteps := 0
	referrals := 0
	refetched := make(map[string]bool)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		qn, qt := name, qtype
		if minimize {
			if m, ok := minimizedName(name, known, minSteps); ok {
				qn, qt = m, dns.TypeA
			}
		}
		full := qn == name && qt == qtype
		maxTimeouts := 0
		if !full {
			maxTimeouts = minimiseTimeouts
		}
		sr, err := r.query(ctx, st, zone, ns, qn, qt, useECS && full, maxTimeouts)
		if err != nil {
			if errors.Is(err, errNoAddrs) && zone != "." && !refetched[zone] {
				refetched[zone] = true
				r.cache.delSet(zone, dns.TypeNS)
				zone, ns = r.findCut(ctx, zone, dns.TypeDS)
				known = zone
				continue
			}
			if !full && minimize && !errors.Is(err, errBudget) && ctx.Err() == nil {
				minimize = false
				continue
			}
			return nil, err
		}
		switch sr.kind {
		case kindReferral:
			referrals++
			if referrals > maxReferrals {
				return nil, errReferrals
			}
			ns = r.storeReferral(sr, zone)
			if ns == nil {
				return nil, fmt.Errorf("%w: referral to %s from %s", errMalformed, sr.child, sr.from)
			}
			zone = sr.child
			known = sr.child
			if r.opts.PrefetchKey && st.validate && r.cache.getSet(zone, dns.TypeDS, trustAnswer) != nil {
				r.prefetchKey(ctx, st, zone)
			}
		case kindAnswer, kindNoData:
			if !full {
				known = qn
				minSteps++
				continue
			}
			if sr.kind == kindAnswer {
				sets := r.storeAnswer(sr, zone, qn, qt)
				if len(sets) == 0 {
					return nil, fmt.Errorf("%w: answer for %s from %s", errMalformed, qn, sr.from)
				}
				return &lookupResult{sets: sets}, nil
			}
			return &lookupResult{neg: r.storeNegative(sr, zone, qn, qt)}, nil
		case kindNXDomain:
			if !full {
				n := r.storeNegative(sr, zone, qn, qt)
				if st.validate {
					if sec, _, err := r.validateNeg(ctx, st, n); err == nil && sec == secSecure {
						return &lookupResult{neg: deriveNX(n, name, qtype)}, nil
					}
				}
				minimize = false
				continue
			}
			return &lookupResult{neg: r.storeNegative(sr, zone, qn, qt)}, nil
		}
	}
}

func (r *Resolver) addrTypes() []uint16 {
	switch {
	case r.opts.NoIPv4:
		return []uint16{dns.TypeAAAA}
	case r.opts.NoIPv6:
		return []uint16{dns.TypeA}
	}
	return []uint16{dns.TypeA, dns.TypeAAAA}
}

func (r *Resolver) familyAllowed(a netip.Addr) bool {
	if a.Is4() || a.Is4In6() {
		return !r.opts.NoIPv4
	}
	return !r.opts.NoIPv6
}

func addrsOf(s *rrset) []netip.Addr {
	var out []netip.Addr
	for _, rr := range s.rrs {
		switch x := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(x.A.To4()); ok {
				out = append(out, a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(x.AAAA.To16()); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

func nsHosts(ns *rrset) []string {
	var out []string
	for _, rr := range ns.rrs {
		if x, ok := rr.(*dns.NS); ok {
			out = append(out, dns.CanonicalName(x.Ns))
			if len(out) >= maxNSHosts {
				break
			}
		}
	}
	return out
}

func (r *Resolver) queryable(a netip.Addr) bool {
	if !a.IsLoopback() && !a.IsUnspecified() {
		return true
	}
	return r.hints.has(a)
}

func (r *Resolver) cachedAddrs(zone string, ns *rrset, parent bool) ([]netip.Addr, []string) {
	var addrs []netip.Addr
	var missing []string
	for _, host := range nsHosts(ns) {
		var got []netip.Addr
		unknown := false
		for _, t := range r.addrTypes() {
			known := false
			if parent {
				if s := r.cache.getParent(host, t); s != nil {
					known = true
					got = append(got, addrsOf(s)...)
				}
			}
			if s := r.cache.getSet(host, t, trustGlue); s != nil {
				known = true
				got = append(got, addrsOf(s)...)
			} else if n := r.cache.getNeg(host, t); n != nil {
				known = true
			}
			if !known {
				unknown = true
			}
		}
		addrs = append(addrs, got...)
		if len(got) == 0 && unknown {
			missing = append(missing, host)
		}
	}
	if zone == "." && len(addrs) == 0 {
		for _, host := range nsHosts(ns) {
			addrs = append(addrs, r.hints.addrs[host]...)
		}
		if len(addrs) == 0 {
			for _, as := range r.hints.addrs {
				addrs = append(addrs, as...)
			}
		}
	}
	return addrs, missing
}

func targetFetch(depth int) int {
	switch depth {
	case 0:
		return 3
	case 1:
		return 2
	}
	return 1
}

type targetResult struct {
	host  string
	addrs []netip.Addr
	nx    bool
	fatal bool
}

func (r *Resolver) resolveNSAddrs(ctx context.Context, st *reqState, zone string, missing []string, done map[string]bool) ([]netip.Addr, bool) {
	var todo []string
	for _, h := range missing {
		if !done[h] {
			todo = append(todo, h)
		}
	}
	if len(todo) == 0 || st.depth >= maxDepth || st.nxExceeded() {
		return nil, false
	}
	rand.Shuffle(len(todo), func(i, j int) { todo[i], todo[j] = todo[j], todo[i] })
	n := st.reserveTargets(zone, min(len(todo), targetFetch(st.depth)))
	if n == 0 {
		return nil, false
	}
	todo = todo[:n]
	types := r.addrTypes()
	results := make(chan targetResult, len(todo)*len(types))
	var wg sync.WaitGroup
	for _, host := range todo {
		done[host] = true
		for _, t := range types {
			c := st.fork()
			c.depth = st.depth + 1
			wg.Add(1)
			go func(host string, t uint16) {
				defer wg.Done()
				defer r.recoverPanic(nil)
				res := targetResult{host: host}
				ch, err := r.resolveChain(ctx, c, host, t, false)
				if err != nil {
					res.fatal = errors.Is(err, errBudget) || ctx.Err() != nil
					results <- res
					return
				}
				for _, s := range ch.sets {
					if s.rtype == t {
						res.addrs = append(res.addrs, addrsOf(s)...)
					}
				}
				res.nx = ch.neg != nil && ch.neg.rcode == dns.RcodeNameError
				results <- res
			}(host, t)
		}
	}
	wg.Wait()
	close(results)
	var out []netip.Addr
	nxHosts := make(map[string]bool)
	for res := range results {
		out = append(out, res.addrs...)
		if res.nx {
			nxHosts[res.host] = true
		}
	}
	st.targetNX.Add(int32(len(nxHosts)))
	return out, true
}

type step struct {
	zone        string
	qn          string
	qt          uint16
	sendECS     bool
	maxTimeouts int
	expectSig   bool
	tried       map[netip.Addr]bool
	done        map[string]bool
	extra       []netip.Addr
	attempts    int
	timeouts    int
	empties     int
	lastErr     error
	fallback    *serverResponse
}

func (r *Resolver) dnssecExpected(zone string) bool {
	if !r.dnssecEnabled() {
		return false
	}
	if z := r.cache.getKeys(zone); z != nil {
		return z.status == secSecure && dnssec.EqualNames(z.zone, zone)
	}
	if zone == "." {
		return true
	}
	ds := r.cache.getSet(zone, dns.TypeDS, trustAnswer)
	if ds == nil {
		return false
	}
	if sec, _ := ds.status(); sec == secBogus {
		return false
	}
	var list []*dns.DS
	for _, rr := range ds.rrs {
		if d, ok := rr.(*dns.DS); ok {
			list = append(list, d)
		}
	}
	return dnssec.HasSupportedDS(list)
}

func (r *Resolver) parentNS(zone string) *rrset {
	if zone == "." {
		return &rrset{name: ".", rtype: dns.TypeNS, rrs: r.hints.ns, trust: trustGlue, zone: "."}
	}
	return r.cache.getParent(zone, dns.TypeNS)
}

func (r *Resolver) query(ctx context.Context, st *reqState, zone string, ns *rrset, qn string, qt uint16, sendECS bool, maxTimeouts int) (*serverResponse, error) {
	if zone == "." && r.local != nil {
		if m := r.local.answer(qn, qt); m != nil {
			kind, child := classify(m, ".", qn, qt)
			sanitize(m, ".")
			if kind != kindFail && kind != kindLame {
				return &serverResponse{msg: m, kind: kind, child: child}, nil
			}
		}
	}
	sp := &step{
		zone:        zone,
		qn:          qn,
		qt:          qt,
		sendECS:     sendECS,
		maxTimeouts: maxTimeouts,
		expectSig:   st.validate && r.dnssecExpected(zone),
		tried:       make(map[netip.Addr]bool),
		done:        make(map[string]bool),
		lastErr:     errNoServers,
	}
	sr, err := r.tryServers(ctx, st, sp, ns, false)
	if sr != nil || err != nil {
		return sr, err
	}
	if sp.fallback == nil {
		if pns := r.parentNS(zone); pns != nil {
			st.parentNS.Store(true)
			sp.extra = nil
			sr, err = r.tryServers(ctx, st, sp, pns, true)
			if sr != nil || err != nil {
				return sr, err
			}
		}
	}
	if sp.fallback != nil {
		return sp.fallback, nil
	}
	if sp.attempts == 0 {
		return nil, fmt.Errorf("%w for zone %s", errNoAddrs, zone)
	}
	return nil, sp.lastErr
}

func emptyMsg(m *dns.Msg) bool {
	if len(m.Answer) > 0 || len(m.Ns) > 0 {
		return false
	}
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			return false
		}
	}
	return true
}

func hasRRSIG(m *dns.Msg) bool {
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				return true
			}
		}
	}
	return false
}

func (r *Resolver) tryServers(ctx context.Context, st *reqState, sp *step, ns *rrset, parent bool) (*serverResponse, error) {
	limit := sp.attempts + maxServersPerStep
	for sp.attempts < limit {
		cached, missing := r.cachedAddrs(sp.zone, ns, parent)
		var addrs []netip.Addr
		seen := make(map[netip.Addr]bool)
		for _, a := range append(cached, sp.extra...) {
			if !sp.tried[a] && !seen[a] && r.familyAllowed(a) && r.queryable(a) {
				seen[a] = true
				addrs = append(addrs, a)
			}
		}
		if len(addrs) == 0 {
			more, ok := r.resolveNSAddrs(ctx, st, sp.zone, missing, sp.done)
			if !ok {
				return nil, nil
			}
			sp.extra = append(sp.extra, more...)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if st.exhausted() {
				return nil, errBudget
			}
			continue
		}
		for _, a := range r.infra.pick(addrs, sp.zone, st.avoid, limit-sp.attempts) {
			sp.attempts++
			sp.tried[a] = true
			sr, err := r.send(ctx, st, a, sp.zone, sp.qn, sp.qt, sp.sendECS)
			if err != nil {
				sp.lastErr = err
				if errors.Is(err, errBudget) || ctx.Err() != nil {
					return nil, err
				}
				if errors.Is(err, errTimeout) {
					sp.timeouts++
					if sp.maxTimeouts > 0 && sp.timeouts >= sp.maxTimeouts {
						return nil, err
					}
				}
				continue
			}
			sr.kind, sr.child = classify(sr.msg, sp.zone, sp.qn, sp.qt)
			sanitize(sr.msg, sp.zone)
			switch sr.kind {
			case kindLame:
				r.infra.markLame(a, sp.zone)
				sp.lastErr = fmt.Errorf("recursor: lame response from %s for %s %s in zone %s (%s)", a, sp.qn, dns.TypeToString[sp.qt], sp.zone, describeResponse(sr.msg))
				continue
			case kindFail:
				sp.lastErr = fmt.Errorf("recursor: %s from %s", dns.RcodeToString[sr.msg.Rcode], a)
				continue
			}
			if sr.kind == kindNoData && emptyMsg(sr.msg) {
				sp.empties++
				if sp.empties < emptyNoDataRetry {
					if sp.fallback == nil {
						sp.fallback = sr
					}
					sp.lastErr = fmt.Errorf("%w from %s", errEmptyNoData, a)
					continue
				}
			}
			if sp.expectSig && sp.attempts <= dnssecLameDetect && !hasRRSIG(sr.msg) {
				if sp.fallback == nil {
					sp.fallback = sr
				}
				sp.lastErr = fmt.Errorf("%w from %s", errDNSSECLame, a)
				continue
			}
			return sr, nil
		}
	}
	return nil, nil
}

func (r *Resolver) buildQuery(qn string, qt uint16, useEDNS, useECS bool, ecs *dns.EDNS0_SUBNET) *dns.Msg {
	q := new(dns.Msg)
	q.Id = dns.Id()
	q.Question = []dns.Question{{Name: qn, Qtype: qt, Qclass: dns.ClassINET}}
	if useEDNS {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(ednsSize)
		if r.dnssecEnabled() {
			opt.SetDo()
		}
		if useECS && ecs != nil {
			c := *ecs
			c.SourceScope = 0
			opt.Option = append(opt.Option, &c)
		}
		q.Extra = []dns.RR{opt}
	}
	return q
}

func ednsRejected(m *dns.Msg) bool {
	switch m.Rcode {
	case dns.RcodeFormatError, dns.RcodeNotImplemented, dns.RcodeBadVers:
		return true
	}
	return false
}

func (r *Resolver) send(ctx context.Context, st *reqState, addr netip.Addr, zone, qn string, qt uint16, sendECS bool) (*serverResponse, error) {
	useEDNS := !r.infra.noEDNS(addr, zone)
	useECS := sendECS && useEDNS && st.ecs != nil && !r.infra.noECS(addr)
	fellBack := false
	for retry := 0; ; retry++ {
		if !st.spend() {
			return nil, errBudget
		}
		q := r.buildQuery(qn, qt, useEDNS, useECS, st.ecs)
		resp, err := r.exchangeOnce(ctx, addr, q)
		if err != nil {
			return nil, err
		}
		if useEDNS && retry < 2 && ednsRejected(resp) {
			if useECS {
				r.infra.setNoECS(addr)
				useECS = false
				continue
			}
			useEDNS = false
			fellBack = true
			continue
		}
		if useEDNS {
			r.infra.setEDNS(addr, zone, true)
		} else if fellBack && !r.dnssecExpected(zone) {
			switch resp.Rcode {
			case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeYXDomain:
				r.infra.setEDNS(addr, zone, false)
			}
		}
		sr := &serverResponse{msg: resp, from: addr, sentECS: useECS}
		if useECS {
			if e := dnsutils.GetMsgECS(resp); e != nil {
				sr.scope = e.SourceScope
			}
		}
		return sr, nil
	}
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func (r *Resolver) timedExchange(ctx context.Context, addr netip.Addr, q *dns.Msg, p proto, timeout time.Duration) (*dns.Msg, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	resp, err := r.ex.exchange(cctx, addr, q, p)
	if err != nil {
		if ctx.Err() == nil {
			r.infra.failure(addr, timeout)
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %s: %v", errTimeout, addr, err)
		}
		return nil, err
	}
	r.infra.success(addr, time.Since(start))
	return resp, nil
}

func (r *Resolver) exchangeOnce(ctx context.Context, addr netip.Addr, q *dns.Msg) (*dns.Msg, error) {
	r.upstream.Add(1)
	timeout := r.infra.timeout(addr)
	if r.opts.OpportunisticDoT {
		switch r.infra.dotStatus(addr) {
		case dotOK:
			r.dotQs.Add(1)
			resp, err := r.timedExchange(ctx, addr, q, protoDoT, clampDuration(3*timeout, 1500*time.Millisecond, probeTimeout))
			if err == nil {
				return resp, nil
			}
			if ctx.Err() != nil {
				return nil, err
			}
			r.infra.setDoT(addr, false)
		case dotUnknown:
			r.startProbe(addr)
		}
	}
	resp, err := r.timedExchange(ctx, addr, q, protoUDP, timeout)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		return r.timedExchange(ctx, addr, q, protoTCP, clampDuration(2*timeout, 1500*time.Millisecond, probeTimeout))
	}
	return resp, nil
}

func (r *Resolver) startProbe(addr netip.Addr) {
	if !r.infra.beginProbe(addr) {
		return
	}
	select {
	case r.probeSem <- struct{}{}:
	default:
		r.infra.endProbe(addr)
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { <-r.probeSem }()
		defer r.recoverPanic(nil)
		ctx, cancel := context.WithTimeout(r.ctx, probeTimeout)
		defer cancel()
		err := r.ex.probeDoT(ctx, addr)
		if r.ctx.Err() != nil {
			r.infra.endProbe(addr)
			return
		}
		r.infra.setDoT(addr, err == nil)
	}()
}

func sanitizeSection(rrs []dns.RR, zone string, extra bool) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			if extra {
				out = append(out, rr)
			}
			continue
		}
		if h.Class != dns.ClassINET {
			continue
		}
		h.Name = dns.CanonicalName(h.Name)
		if !dns.IsSubDomain(zone, h.Name) {
			continue
		}
		if extra && h.Rrtype != dns.TypeA && h.Rrtype != dns.TypeAAAA {
			continue
		}
		if x, ok := rr.(*dns.RRSIG); ok {
			x.SignerName = dns.CanonicalName(x.SignerName)
		}
		out = append(out, rr)
	}
	return out
}

func sanitize(m *dns.Msg, zone string) {
	m.Answer = sanitizeSection(m.Answer, zone, false)
	m.Ns = sanitizeSection(m.Ns, zone, false)
	m.Extra = sanitizeSection(m.Extra, zone, true)
}

func dnameFor(m *dns.Msg, zone, qn string) *dns.DNAME {
	for _, rr := range m.Answer {
		d, ok := rr.(*dns.DNAME)
		if !ok || d.Hdr.Class != dns.ClassINET {
			continue
		}
		owner := dns.CanonicalName(d.Hdr.Name)
		if dns.IsSubDomain(zone, owner) && dnssec.IsStrictSubDomain(owner, qn) {
			return d
		}
	}
	return nil
}

func classify(m *dns.Msg, zone, qn string, qt uint16) (respKind, string) {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		if m.Rcode == dns.RcodeRefused || m.Rcode == dns.RcodeNotAuth {
			return kindLame, ""
		}
		return kindFail, ""
	}
	for _, rr := range m.Answer {
		h := rr.Header()
		if h.Class == dns.ClassINET && dnssec.EqualNames(h.Name, qn) && (h.Rrtype == qt || h.Rrtype == dns.TypeCNAME) {
			return kindAnswer, ""
		}
	}
	if dnameFor(m, zone, qn) != nil {
		return kindAnswer, ""
	}
	if m.Rcode == dns.RcodeNameError {
		if m.RecursionAvailable && !m.Authoritative {
			return kindLame, ""
		}
		return kindNXDomain, ""
	}
	hasSOA := false
	child := ""
	for _, rr := range m.Ns {
		if rr.Header().Class != dns.ClassINET {
			continue
		}
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			hasSOA = true
		case dns.TypeNS:
			if child == "" {
				child = dns.CanonicalName(rr.Header().Name)
			}
		}
	}
	if !hasSOA && child != "" && child != zone {
		if qt == dns.TypeDS && child == qn && dnssec.IsStrictSubDomain(zone, child) && len(m.Answer) == 0 {
			return kindNoData, ""
		}
		if dnssec.IsStrictSubDomain(zone, child) && dns.IsSubDomain(child, qn) && !(qt == dns.TypeDS && child == qn) {
			return kindReferral, child
		}
		return kindLame, ""
	}
	if len(m.Answer) == 0 {
		if !m.Authoritative && m.RecursionAvailable {
			return kindLame, ""
		}
		return kindNoData, ""
	}
	return kindLame, ""
}

func describeResponse(m *dns.Msg) string {
	return fmt.Sprintf("rcode=%s aa=%v ra=%v answer=%d authority=%d additional=%d",
		dns.RcodeToString[m.Rcode], m.Authoritative, m.RecursionAvailable, len(m.Answer), len(m.Ns), len(m.Extra))
}

func group(rrs []dns.RR) []*rrset {
	var out []*rrset
	idx := make(map[string]*rrset)
	for _, rr := range rrs {
		if _, ok := rr.(*dns.RRSIG); ok {
			continue
		}
		h := rr.Header()
		k := setKey(h.Name, h.Rrtype)
		s := idx[k]
		if s == nil {
			s = &rrset{name: h.Name, rtype: h.Rrtype}
			idx[k] = s
			out = append(out, s)
		}
		dup := false
		for _, x := range s.rrs {
			if dns.IsDuplicate(x, rr) {
				dup = true
				break
			}
		}
		if !dup {
			s.rrs = append(s.rrs, rr)
		}
	}
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if s := idx[setKey(sig.Hdr.Name, sig.TypeCovered)]; s != nil {
			s.sigs = append(s.sigs, sig)
		}
	}
	for _, s := range out {
		ttl := s.minTTL()
		for _, rr := range s.rrs {
			rr.Header().Ttl = ttl
		}
	}
	return out
}

func findSet(sets []*rrset, name string, t uint16) *rrset {
	for _, s := range sets {
		if s.name == name && s.rtype == t {
			return s
		}
	}
	return nil
}

func (r *Resolver) finishSet(s *rrset, zone string, from netip.Addr, trust trustLevel, max time.Duration) {
	now := r.now()
	s.zone = zone
	s.server = from
	s.trust = trust
	s.expire = now.Add(capTTL(s.minTTL(), max))
	if e, ok := sigExpiry(s.sigs, now); ok && e.Before(s.expire) {
		s.expire = e
	}
	s.prefetch = prefetchAt(now, s.expire)
}

func (r *Resolver) proofSets(sets []*rrset, zone string, from netip.Addr) []*rrset {
	var out []*rrset
	for _, s := range sets {
		if s.rtype == dns.TypeNSEC || s.rtype == dns.TypeNSEC3 {
			r.finishSet(s, zone, from, trustAuthority, maxNegativeTTL)
			out = append(out, s)
		}
	}
	return out
}

func (r *Resolver) storeReferral(sr *serverResponse, zone string) *rrset {
	m := sr.msg
	sets := group(m.Ns)
	ns := findSet(sets, sr.child, dns.TypeNS)
	if ns == nil {
		return nil
	}
	r.finishSet(ns, zone, sr.from, trustAuthority, maxCacheTTL)
	r.cache.putSet(ns)
	r.cache.putParent(ns)
	if ds := findSet(sets, sr.child, dns.TypeDS); ds != nil {
		r.finishSet(ds, zone, sr.from, trustAnswer, maxCacheTTL)
		r.cache.putSet(ds)
	} else if proofs := r.proofSets(sets, zone, sr.from); len(proofs) > 0 {
		n := &negative{
			name:   sr.child,
			qtype:  dns.TypeDS,
			rcode:  dns.RcodeSuccess,
			proof:  proofs,
			zone:   zone,
			server: sr.from,
			ecsOK:  true,
			expire: proofs[0].expire,
		}
		for _, p := range proofs[1:] {
			if p.expire.Before(n.expire) {
				n.expire = p.expire
			}
		}
		n.prefetch = prefetchAt(r.now(), n.expire)
		r.cache.putNeg(n)
	}
	hosts := make(map[string]bool)
	for _, h := range nsHosts(ns) {
		hosts[h] = true
	}
	for _, s := range group(m.Extra) {
		if !hosts[s.name] || (s.rtype != dns.TypeA && s.rtype != dns.TypeAAAA) {
			continue
		}
		r.finishSet(s, zone, sr.from, trustGlue, maxCacheTTL)
		r.cache.putSet(s)
		r.cache.putParent(s)
	}
	return ns
}

func (r *Resolver) ecsFlags(sr *serverResponse) (cacheable, ecsOK bool) {
	if sr.sentECS && sr.scope > 0 {
		return false, false
	}
	if sr.sentECS {
		return true, true
	}
	if sr.from.IsValid() {
		return true, r.infra.noECS(sr.from)
	}
	return true, true
}

func (r *Resolver) storeAnswer(sr *serverResponse, zone, qn string, qt uint16) []*rrset {
	m := sr.msg
	sets := group(m.Answer)
	cacheable, ecsOK := r.ecsFlags(sr)
	finish := func(s *rrset) {
		r.finishSet(s, zone, sr.from, trustAnswer, maxCacheTTL)
		s.ecsOK = ecsOK
		s.scope = sr.scope
		if cacheable {
			r.cache.putSet(s)
		}
	}
	if s := findSet(sets, qn, qt); s != nil {
		for _, sig := range s.sigs {
			if int(sig.Labels) < dns.CountLabel(qn) {
				s.proof = r.proofSets(group(m.Ns), zone, sr.from)
				break
			}
		}
		finish(s)
		return []*rrset{s}
	}
	d := dnameFor(m, zone, qn)
	if s := findSet(sets, qn, dns.TypeCNAME); s != nil && d == nil {
		s.rrs = s.rrs[:1]
		for _, sig := range s.sigs {
			if int(sig.Labels) < dns.CountLabel(qn) {
				s.proof = r.proofSets(group(m.Ns), zone, sr.from)
				break
			}
		}
		finish(s)
		return []*rrset{s}
	}
	if d == nil {
		return nil
	}
	ds := findSet(sets, dns.CanonicalName(d.Hdr.Name), dns.TypeDNAME)
	if ds == nil {
		return nil
	}
	ds.rrs = ds.rrs[:1]
	finish(ds)
	target := synthesizeDNAME(qn, ds.rrs[0].(*dns.DNAME))
	c := &rrset{
		name:  qn,
		rtype: dns.TypeCNAME,
		rrs: []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: qn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ds.rrs[0].Header().Ttl},
			Target: target,
		}},
		synth: true,
	}
	r.finishSet(c, zone, sr.from, trustAnswer, maxCacheTTL)
	c.expire = ds.expire
	c.prefetch = ds.prefetch
	c.ecsOK = ecsOK
	c.scope = sr.scope
	return []*rrset{ds, c}
}

func synthesizeDNAME(qn string, d *dns.DNAME) string {
	prefix := qn[:len(qn)-len(d.Hdr.Name)]
	if d.Hdr.Name == "." {
		prefix = qn
	}
	target := dns.CanonicalName(d.Target)
	if target == "." {
		return dns.Fqdn(prefix)
	}
	return prefix + target
}

func (r *Resolver) storeNegative(sr *serverResponse, zone, qn string, qt uint16) *negative {
	m := sr.msg
	sets := group(m.Ns)
	n := &negative{
		name:   qn,
		qtype:  qt,
		rcode:  m.Rcode,
		zone:   zone,
		server: sr.from,
		scope:  sr.scope,
	}
	cacheable, ecsOK := r.ecsFlags(sr)
	n.ecsOK = ecsOK
	var ttl uint32
	haveTTL := false
	for _, s := range sets {
		if s.rtype == dns.TypeSOA && dns.IsSubDomain(s.name, qn) {
			r.finishSet(s, zone, sr.from, trustAuthority, maxNegativeTTL)
			s.rrs = s.rrs[:1]
			n.soa = s
			soa := s.rrs[0].(*dns.SOA)
			ttl = soa.Hdr.Ttl
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			haveTTL = true
			break
		}
	}
	n.proof = r.proofSets(sets, zone, sr.from)
	if !haveTTL {
		cacheable = false
	}
	now := r.now()
	n.expire = now.Add(capTTL(ttl, maxNegativeTTL))
	if n.soa != nil {
		n.expire = minTime(n.expire, n.soa.expire)
	}
	for _, p := range n.proof {
		n.expire = minTime(n.expire, p.expire)
	}
	n.prefetch = prefetchAt(now, n.expire)
	if n.soa != nil {
		n.soa.expire = n.expire
		n.soa.prefetch = n.prefetch
	}
	for _, p := range n.proof {
		p.expire = n.expire
		p.prefetch = n.prefetch
	}
	if !n.expire.After(now) {
		cacheable = false
	}
	if cacheable && ttl > 0 {
		r.cache.putNeg(n)
	}
	return n
}

func (r *Resolver) rootNS(ctx context.Context) *rrset {
	if s := r.cache.getSet(".", dns.TypeNS, trustAuthority); s != nil {
		return s
	}
	hints := &rrset{name: ".", rtype: dns.TypeNS, rrs: r.hints.ns, trust: trustGlue, zone: "."}
	if r.local != nil && r.local.active() {
		return hints
	}
	r.primeSF.Do("prime", func() (any, error) {
		r.prime(ctx, hints)
		return nil, nil
	})
	if s := r.cache.getSet(".", dns.TypeNS, trustAuthority); s != nil {
		return s
	}
	return hints
}

func (r *Resolver) prime(ctx context.Context, hints *rrset) {
	var addrs []netip.Addr
	for _, as := range r.hints.addrs {
		for _, a := range as {
			if r.familyAllowed(a) {
				addrs = append(addrs, a)
			}
		}
	}
	st := newReqState(false, nil, nil)
	for _, a := range r.infra.pick(addrs, ".", nil, 3) {
		sr, err := r.send(ctx, st, a, ".", ".", dns.TypeNS, false)
		if err != nil {
			continue
		}
		sanitize(sr.msg, ".")
		if !sr.msg.Authoritative || sr.msg.Rcode != dns.RcodeSuccess {
			continue
		}
		ns := findSet(group(sr.msg.Answer), ".", dns.TypeNS)
		if ns == nil {
			continue
		}
		r.finishSet(ns, ".", a, trustAnswer, maxCacheTTL)
		hosts := make(map[string]bool)
		for _, h := range nsHosts(ns) {
			hosts[h] = true
		}
		for _, s := range group(sr.msg.Extra) {
			if hosts[s.name] && (s.rtype == dns.TypeA || s.rtype == dns.TypeAAAA) {
				r.finishSet(s, ".", a, trustGlue, maxCacheTTL)
				r.cache.putSet(s)
			}
		}
		r.cache.putSet(ns)
		return
	}
}
