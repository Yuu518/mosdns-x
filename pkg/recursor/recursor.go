package recursor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	D "github.com/pmkol/mosdns-x/pkg/upstream/dialer"
)

const (
	defaultCacheSize  = 32768
	sharedTimeout     = 10 * time.Second
	queryBudget       = 200
	maxReferrals      = 30
	maxCNAMEChain     = 12
	maxDepth          = 6
	maxServersPerStep = 5
	maxMinimizeSteps  = 10
	validationBudget  = 16
	ednsSize          = 1232
	maxDoTProbes      = 16
	maxTargets        = 64
	maxDPTargets      = 16
	maxTargetNX       = 5
	maxTargetNXParent = 10
	maxNSHosts        = 20
	emptyNoDataRetry  = 2
	dnssecLameDetect  = 4
	minimiseOneLab    = 4
	minimiseTimeouts  = 3
	maxValRestarts    = 5
	maxPrefetches     = 32
)

var (
	errNoRootHints   = errors.New("recursor: no root hints")
	errNoTrustAnchor = errors.New("recursor: no root trust anchor")
	errBudget        = errors.New("recursor: query budget exhausted")
	errDepth         = errors.New("recursor: dependency too deep")
	errLoop          = errors.New("recursor: dependency loop")
	errNoServers     = errors.New("recursor: no server responded")
	errNoAddrs       = errors.New("recursor: no usable name server address")
	errReferrals     = errors.New("recursor: too many referrals")
	errCNAMEChain    = errors.New("recursor: cname chain too long or looped")
	errClosed        = errors.New("recursor: resolver closed")
	errTimeout       = errors.New("recursor: query timed out")
	errEmptyNoData   = errors.New("recursor: empty response")
	errDNSSECLame    = errors.New("recursor: response is missing dnssec records")
	errMalformed     = errors.New("recursor: malformed response")
	errInternal      = errors.New("recursor: internal error")
)

func (r *Resolver) recoverPanic(err *error) {
	p := recover()
	if p == nil {
		return
	}
	r.logger.Error("recursor panic", zap.Any("panic", p), zap.Stack("stack"))
	if err != nil {
		*err = fmt.Errorf("%w: %v", errInternal, p)
	}
}

type Opts struct {
	Dialer           D.Dialer
	RootHints        []dns.RR
	TrustAnchors     []dns.RR
	DisableDNSSEC    bool
	DisableQNameMin  bool
	NoIPv4           bool
	NoIPv6           bool
	CacheSize        int
	LocalRoot        bool
	LocalRootSource  string
	LocalRootFile    string
	OpportunisticDoT bool
	Prefetch         bool
	PrefetchKey      bool
	AutoTrustFile    string
	Logger           *zap.Logger

	exchanger           exchanger
	now                 func() time.Time
	localRootInterval   time.Duration
	localRootHTTPClient httpDoer
	autoTrustInterval   time.Duration
}

type Stats struct {
	Queries         uint64
	Errors          uint64
	UpstreamQueries uint64
	DoTQueries      uint64
	CacheHits       uint64
	Secure          uint64
	Insecure        uint64
	Bogus           uint64
	Synthesized     uint64
	Prefetches      uint64
	CacheSize       int
	LocalRootSerial uint32
}

type Resolver struct {
	opts    Opts
	logger  *zap.Logger
	now     func() time.Time
	ex      exchanger
	cache   *cache
	infra   *infra
	hints   *rootHints
	anchors []*dns.DS
	sf      singleflight.Group
	primeSF singleflight.Group
	local   *localRoot
	auto    *autoTrust

	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	probeSem    chan struct{}
	prefetchSem chan struct{}
	prefetching sync.Map

	queries   atomic.Uint64
	errs      atomic.Uint64
	upstream  atomic.Uint64
	dotQs     atomic.Uint64
	cacheHits atomic.Uint64
	secure    atomic.Uint64
	insecure  atomic.Uint64
	bogus     atomic.Uint64
	synth     atomic.Uint64
	prefetchs atomic.Uint64
}

func New(opts Opts) (*Resolver, error) {
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = defaultCacheSize
	}
	if opts.NoIPv4 && opts.NoIPv6 {
		return nil, errors.New("recursor: both ipv4 and ipv6 are disabled")
	}
	hintRRs := opts.RootHints
	if len(hintRRs) == 0 {
		hintRRs = mustParseRRs(builtinRootHints)
	}
	hints, err := newRootHints(hintRRs)
	if err != nil {
		return nil, err
	}
	anchorRRs := opts.TrustAnchors
	if len(anchorRRs) == 0 {
		anchorRRs = mustParseRRs(builtinTrustAnchors)
	}
	anchors, err := parseTrustAnchors(anchorRRs)
	if err != nil {
		return nil, err
	}

	ex := opts.exchanger
	if ex == nil {
		d := opts.Dialer
		if d == nil {
			d, err = D.NewDialer(D.DialerOpts{Dialer: &net.Dialer{}})
			if err != nil {
				return nil, err
			}
		}
		ex = newNetExchanger(d, opts.Logger)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &Resolver{
		opts:        opts,
		logger:      opts.Logger,
		now:         opts.now,
		ex:          ex,
		cache:       newCache(opts.CacheSize, opts.now),
		infra:       newInfra(opts.now),
		hints:       hints,
		anchors:     anchors,
		ctx:         ctx,
		cancel:      cancel,
		probeSem:    make(chan struct{}, maxDoTProbes),
		prefetchSem: make(chan struct{}, maxPrefetches),
	}
	if opts.AutoTrustFile != "" && !opts.DisableDNSSEC {
		a, err := newAutoTrust(opts.AutoTrustFile, anchors, opts.Logger)
		if err != nil {
			cancel()
			return nil, err
		}
		r.auto = a
		r.startAutoTrust()
	}
	if opts.LocalRoot {
		r.local = newLocalRoot(r)
		r.local.start()
	}
	return r, nil
}

func (r *Resolver) Close() error {
	r.cancel()
	r.wg.Wait()
	return r.ex.close()
}

func (r *Resolver) Stats() Stats {
	s := Stats{
		Queries:         r.queries.Load(),
		Errors:          r.errs.Load(),
		UpstreamQueries: r.upstream.Load(),
		DoTQueries:      r.dotQs.Load(),
		CacheHits:       r.cacheHits.Load(),
		Secure:          r.secure.Load(),
		Insecure:        r.insecure.Load(),
		Bogus:           r.bogus.Load(),
		Synthesized:     r.synth.Load(),
		Prefetches:      r.prefetchs.Load(),
		CacheSize:       r.cache.len(),
	}
	if r.local != nil {
		s.LocalRootSerial = r.local.serial()
	}
	return s
}

func (r *Resolver) dnssecEnabled() bool {
	return !r.opts.DisableDNSSEC
}

type reqShared struct {
	budget       atomic.Int64
	targetNX     atomic.Int32
	parentNS     atomic.Bool
	vbudget      *dnssec.Budget
	mu           sync.Mutex
	targets      int
	dpTargets    map[string]int
	bogusZones   []string
	bogusServers []netip.Addr
	keyFetch     map[string]chan struct{}
}

func newReqShared() *reqShared {
	sh := &reqShared{
		vbudget:   dnssec.NewBudget(validationBudget),
		dpTargets: make(map[string]int),
		keyFetch:  make(map[string]chan struct{}),
	}
	sh.budget.Store(queryBudget)
	return sh
}

func (sh *reqShared) spend() bool {
	return sh.budget.Add(-1) >= 0
}

func (sh *reqShared) exhausted() bool {
	return sh.budget.Load() <= 0
}

func (sh *reqShared) nxExceeded() bool {
	limit := int32(maxTargetNX)
	if sh.parentNS.Load() {
		limit = maxTargetNXParent
	}
	return sh.targetNX.Load() > limit
}

func (sh *reqShared) reserveTargets(zone string, n int) int {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	n = min(n, maxTargets-sh.targets, maxDPTargets-sh.dpTargets[zone])
	if n <= 0 {
		return 0
	}
	sh.targets += n
	sh.dpTargets[zone] += n
	return n
}

func (sh *reqShared) addBogusZone(zone string) {
	sh.mu.Lock()
	sh.bogusZones = append(sh.bogusZones, zone)
	sh.mu.Unlock()
}

func (sh *reqShared) addBogusServer(a netip.Addr) {
	if !a.IsValid() {
		return
	}
	sh.mu.Lock()
	sh.bogusServers = append(sh.bogusServers, a)
	sh.mu.Unlock()
}

func (sh *reqShared) takeBogus() ([]string, []netip.Addr) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	z, a := sh.bogusZones, sh.bogusServers
	sh.bogusZones, sh.bogusServers = nil, nil
	return z, a
}

type reqState struct {
	*reqShared
	depth    int
	stack    map[string]bool
	avoid    map[netip.Addr]bool
	ecs      *dns.EDNS0_SUBNET
	validate bool
	noWait   bool
}

func newReqState(validate bool, ecs *dns.EDNS0_SUBNET, avoid map[netip.Addr]bool) *reqState {
	return newReqStateShared(newReqShared(), validate, ecs, avoid)
}

func newReqStateShared(sh *reqShared, validate bool, ecs *dns.EDNS0_SUBNET, avoid map[netip.Addr]bool) *reqState {
	return &reqState{
		reqShared: sh,
		stack:     make(map[string]bool),
		avoid:     avoid,
		ecs:       ecs,
		validate:  validate,
	}
}

func (st *reqState) fork() *reqState {
	c := *st
	c.stack = maps.Clone(st.stack)
	return &c
}

type answer struct {
	rcode  int
	answer []dns.RR
	ns     []dns.RR
	sec    secStatus
	ede    uint16
	hasEDE bool
	scope  uint8
}

func notImpl(q *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, rcode)
	r.RecursionAvailable = true
	return r
}

func (r *Resolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	r.queries.Add(1)
	if r.ctx.Err() != nil {
		r.errs.Add(1)
		return nil, errClosed
	}
	if q.Opcode != dns.OpcodeQuery {
		return notImpl(q, dns.RcodeNotImplemented), nil
	}
	if len(q.Question) != 1 {
		return notImpl(q, dns.RcodeFormatError), nil
	}
	question := q.Question[0]
	if question.Qclass != dns.ClassINET {
		return notImpl(q, dns.RcodeNotImplemented), nil
	}
	switch question.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeMAILA, dns.TypeMAILB, dns.TypeOPT:
		return notImpl(q, dns.RcodeNotImplemented), nil
	}
	name := dns.CanonicalName(question.Name)
	if _, ok := dns.IsDomainName(name); !ok {
		return notImpl(q, dns.RcodeFormatError), nil
	}
	validate := r.dnssecEnabled() && !q.CheckingDisabled
	ecs := dnsutils.GetMsgECS(q)
	if ecs != nil {
		c := *ecs
		c.SourceScope = 0
		ecs = &c
	}

	key := name + "|" + strconv.Itoa(int(question.Qtype)) + "|" + strconv.FormatBool(validate)
	if ecs != nil {
		key += "|" + ecs.String()
	}
	ch := r.sf.DoChan(key, func() (v any, err error) {
		defer r.recoverPanic(&err)
		sctx, cancel := context.WithTimeout(r.ctx, sharedTimeout)
		defer cancel()
		return r.resolveTop(sctx, name, question.Qtype, validate, ecs)
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			r.errs.Add(1)
			return nil, res.Err
		}
		return r.buildResponse(q, res.Val.(*answer), validate), nil
	case <-ctx.Done():
		r.errs.Add(1)
		return nil, ctx.Err()
	}
}

func isDNSSECType(t uint16) bool {
	switch t {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		return true
	}
	return false
}

func (r *Resolver) buildResponse(q *dns.Msg, a *answer, validate bool) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.RecursionAvailable = true
	resp.Authoritative = false
	resp.Rcode = a.rcode
	qtype := q.Question[0].Qtype
	clientOpt := q.IsEdns0()
	do := clientOpt != nil && clientOpt.Do()
	keep := func(rr dns.RR) bool {
		t := rr.Header().Rrtype
		return do || !isDNSSECType(t) || t == qtype
	}
	for _, rr := range a.answer {
		if keep(rr) {
			resp.Answer = append(resp.Answer, dns.Copy(rr))
		}
	}
	for _, rr := range a.ns {
		if keep(rr) {
			resp.Ns = append(resp.Ns, dns.Copy(rr))
		}
	}
	resp.AuthenticatedData = validate && a.sec == secSecure && (do || q.AuthenticatedData)
	if clientOpt != nil {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(ednsSize)
		opt.SetDo(do)
		if a.hasEDE {
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: a.ede})
		}
		if ecs := dnsutils.GetECS(clientOpt); ecs != nil {
			c := *ecs
			c.SourceScope = a.scope
			opt.Option = append(opt.Option, &c)
		}
		resp.Extra = append(resp.Extra, opt)
	}
	return resp
}

func (r *Resolver) resolveTop(ctx context.Context, name string, qtype uint16, validate bool, ecs *dns.EDNS0_SUBNET) (*answer, error) {
	if validate {
		if b := r.cache.getBogus(name, qtype); b != nil {
			r.bogus.Add(1)
			return &answer{rcode: dns.RcodeServerFailure, sec: secBogus, ede: b.ede, hasEDE: true}, nil
		}
	}
	sh := newReqShared()
	avoid := make(map[netip.Addr]bool)
	for attempt := 0; ; attempt++ {
		st := newReqStateShared(sh, validate, ecs, avoid)
		ch, err := r.resolveChain(ctx, st, name, qtype, true)
		if err != nil {
			return nil, err
		}
		if !validate {
			return r.assemble(ch, secUnchecked, 0), nil
		}
		sec, ede, err := r.validateChain(ctx, st, ch)
		if err != nil {
			return nil, err
		}
		if sec == secBogus {
			if attempt < maxValRestarts && !sh.exhausted() {
				next := r.purge(ch, st, avoid)
				if len(next) > len(avoid) {
					avoid = next
					continue
				}
			}
			r.bogus.Add(1)
			r.cache.putBogus(name, qtype, ede)
			r.logger.Debug("bogus answer", zap.String("name", name), zap.Uint16("qtype", qtype), zap.Uint16("ede", ede))
			return &answer{rcode: dns.RcodeServerFailure, sec: secBogus, ede: ede, hasEDE: true}, nil
		}
		if sec == secSecure {
			r.secure.Add(1)
		} else {
			r.insecure.Add(1)
		}
		return r.assemble(ch, sec, 0), nil
	}
}

func (r *Resolver) purge(ch *chainResult, st *reqState, avoid map[netip.Addr]bool) map[netip.Addr]bool {
	next := maps.Clone(avoid)
	for _, s := range ch.sets {
		if sec, _ := s.status(); sec == secBogus {
			r.cache.delSet(s.name, s.rtype)
			if s.server.IsValid() {
				next[s.server] = true
			}
		}
	}
	if n := ch.neg; n != nil {
		if sec, _ := n.status(); sec == secBogus {
			r.cache.delNeg(n)
			if n.server.IsValid() {
				next[n.server] = true
			}
		}
	}
	zones, servers := st.takeBogus()
	for _, z := range zones {
		r.cache.delKeys(z)
	}
	for _, a := range servers {
		next[a] = true
	}
	return next
}

func (r *Resolver) startPrefetch(name string, qtype uint16, ecs *dns.EDNS0_SUBNET) {
	if r.ctx.Err() != nil {
		return
	}
	key := setKey(name, qtype)
	if ecs != nil {
		key += "|" + ecs.String()
	}
	if _, loaded := r.prefetching.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	select {
	case r.prefetchSem <- struct{}{}:
	default:
		r.prefetching.Delete(key)
		return
	}
	r.prefetchs.Add(1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { <-r.prefetchSem }()
		defer r.prefetching.Delete(key)
		defer r.recoverPanic(nil)
		ctx, cancel := context.WithTimeout(r.ctx, sharedTimeout)
		defer cancel()
		st := newReqState(false, ecs, nil)
		st.stack[setKey(name, qtype)] = true
		if _, err := r.iterate(ctx, st, name, qtype, ecs != nil); err != nil {
			r.logger.Debug("prefetch failed", zap.String("name", name), zap.Uint16("qtype", qtype), zap.Error(err))
		}
	}()
}

func (r *Resolver) maybePrefetch(res *lookupResult, name string, qtype uint16, ecs *dns.EDNS0_SUBNET) {
	now := r.now()
	due := false
	if res.neg != nil {
		due = !now.Before(res.neg.prefetch)
	} else if len(res.sets) > 0 {
		due = !now.Before(res.sets[0].prefetch)
	}
	if due {
		r.startPrefetch(name, qtype, ecs)
	}
}

func (r *Resolver) ttlCopy(rr dns.RR, ttl uint32) dns.RR {
	c := dns.Copy(rr)
	if c.Header().Ttl > ttl {
		c.Header().Ttl = ttl
	}
	return c
}

func (r *Resolver) appendSet(dst []dns.RR, s *rrset) []dns.RR {
	ttl := r.cache.remaining(s.expire)
	for _, rr := range s.rrs {
		dst = append(dst, r.ttlCopy(rr, ttl))
	}
	for _, sig := range s.sigs {
		dst = append(dst, r.ttlCopy(sig, ttl))
	}
	return dst
}

func (r *Resolver) assemble(ch *chainResult, sec secStatus, ede uint16) *answer {
	a := &answer{rcode: dns.RcodeSuccess, sec: sec, ede: ede}
	for _, s := range ch.sets {
		a.answer = r.appendSet(a.answer, s)
		for _, p := range s.proof {
			a.ns = r.appendSet(a.ns, p)
		}
		if s.scope > a.scope {
			a.scope = s.scope
		}
	}
	if n := ch.neg; n != nil {
		a.rcode = n.rcode
		if n.soa != nil {
			a.ns = r.appendSet(a.ns, n.soa)
		}
		for _, p := range n.proof {
			a.ns = r.appendSet(a.ns, p)
		}
		if n.scope > a.scope {
			a.scope = n.scope
		}
		ttl := r.cache.remaining(n.expire)
		for _, rr := range a.ns {
			if rr.Header().Ttl > ttl {
				rr.Header().Ttl = ttl
			}
		}
	}
	return a
}
