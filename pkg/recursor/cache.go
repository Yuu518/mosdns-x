package recursor

import (
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
	"github.com/pmkol/mosdns-x/pkg/dnssec"
)

type secStatus uint32

const (
	secUnchecked secStatus = iota
	secSecure
	secInsecure
	secBogus
)

func (s secStatus) String() string {
	switch s {
	case secSecure:
		return "secure"
	case secInsecure:
		return "insecure"
	case secBogus:
		return "bogus"
	}
	return "unchecked"
}

func worse(a, b secStatus) secStatus {
	if a > b {
		return a
	}
	return b
}

type trustLevel uint8

const (
	trustGlue trustLevel = iota + 1
	trustAuthority
	trustAnswer
)

const (
	maxCacheTTL       = 24 * time.Hour
	maxNegativeTTL    = time.Hour
	bogusTTL          = 60 * time.Second
	cacheShards       = 64
	nsecZonesPerShard = 64
	maxNSECPerZone    = 1024
)

type rrset struct {
	name     string
	rtype    uint16
	rrs      []dns.RR
	sigs     []*dns.RRSIG
	expire   time.Time
	prefetch time.Time
	trust    trustLevel
	zone     string
	server   netip.Addr
	ecsOK    bool
	scope    uint8
	proof    []*rrset
	synth    bool

	sec atomic.Uint32
	ede atomic.Uint32
}

func (s *rrset) status() (secStatus, uint16) {
	return secStatus(s.sec.Load()), uint16(s.ede.Load())
}

func (s *rrset) setStatus(sec secStatus, ede uint16) {
	s.ede.Store(uint32(ede))
	s.sec.Store(uint32(sec))
}

func (s *rrset) minTTL() uint32 {
	var ttl uint32
	first := true
	for _, rr := range s.rrs {
		if t := rr.Header().Ttl; first || t < ttl {
			ttl = t
			first = false
		}
	}
	for _, sig := range s.sigs {
		if t := sig.OrigTtl; t < ttl {
			ttl = t
		}
	}
	return ttl
}

type negative struct {
	name     string
	qtype    uint16
	rcode    int
	soa      *rrset
	proof    []*rrset
	expire   time.Time
	prefetch time.Time
	zone     string
	server   netip.Addr
	ecsOK    bool
	scope    uint8

	sec atomic.Uint32
	ede atomic.Uint32
}

func (n *negative) status() (secStatus, uint16) {
	return secStatus(n.sec.Load()), uint16(n.ede.Load())
}

func (n *negative) setStatus(sec secStatus, ede uint16) {
	n.ede.Store(uint32(ede))
	n.sec.Store(uint32(sec))
}

type bogusEntry struct {
	ede    uint16
	expire time.Time
}

type zoneSec struct {
	zone   string
	status secStatus
	keys   []*dns.DNSKEY
	expire time.Time
	ede    uint16
}

type nsecEntry struct {
	nsec *dns.NSEC
	set  *rrset
}

type nsecZone struct {
	zone    string
	mu      sync.Mutex
	soa     *rrset
	entries []nsecEntry
}

type cache struct {
	now    func() time.Time
	sets   *concurrent_lru.ShardedLRU[*rrset]
	parent *concurrent_lru.ShardedLRU[*rrset]
	negs   *concurrent_lru.ShardedLRU[*negative]
	bogus  *concurrent_lru.ShardedLRU[*bogusEntry]
	keys   *concurrent_lru.ShardedLRU[*zoneSec]
	nsecMu sync.Mutex
	nsecs  *concurrent_lru.ShardedLRU[*nsecZone]
}

func newCache(size int, now func() time.Time) *cache {
	per := size / cacheShards
	if per < 16 {
		per = 16
	}
	negPer := per / 4
	if negPer < 16 {
		negPer = 16
	}
	return &cache{
		now:    now,
		sets:   concurrent_lru.NewShardedLRU[*rrset](cacheShards, per, nil),
		parent: concurrent_lru.NewShardedLRU[*rrset](cacheShards, negPer, nil),
		negs:   concurrent_lru.NewShardedLRU[*negative](cacheShards, negPer, nil),
		bogus:  concurrent_lru.NewShardedLRU[*bogusEntry](cacheShards, negPer, nil),
		keys:   concurrent_lru.NewShardedLRU[*zoneSec](cacheShards, negPer, nil),
		nsecs:  concurrent_lru.NewShardedLRU[*nsecZone](cacheShards, nsecZonesPerShard, nil),
	}
}

func (c *cache) putParent(s *rrset) {
	c.parent.Add(setKey(s.name, s.rtype), s)
}

func (c *cache) getParent(name string, t uint16) *rrset {
	k := setKey(name, t)
	s, ok := c.parent.Get(k)
	if !ok {
		return nil
	}
	if !c.now().Before(s.expire) {
		c.parent.Del(k)
		return nil
	}
	return s
}

func (c *cache) getNX(name string) *negative {
	k := nxKey(name)
	n, ok := c.negs.Get(k)
	if !ok {
		return nil
	}
	if !c.now().Before(n.expire) {
		c.negs.Del(k)
		return nil
	}
	return n
}

func (c *cache) addNSECs(zone string, soa *rrset, sets []*rrset) {
	c.nsecMu.Lock()
	z, ok := c.nsecs.Get(zone)
	if !ok {
		z = &nsecZone{zone: zone}
		c.nsecs.Add(zone, z)
	}
	c.nsecMu.Unlock()
	now := c.now()
	z.mu.Lock()
	defer z.mu.Unlock()
	if soa != nil && (z.soa == nil || soa.expire.After(z.soa.expire)) {
		z.soa = soa
	}
	for _, s := range sets {
		for _, rr := range s.rrs {
			if n, ok := rr.(*dns.NSEC); ok {
				z.insert(nsecEntry{nsec: n, set: s}, now)
			}
		}
	}
}

func (z *nsecZone) search(name string) int {
	return sort.Search(len(z.entries), func(i int) bool {
		return dnssec.CompareNames(z.entries[i].nsec.Hdr.Name, name) > 0
	}) - 1
}

func (z *nsecZone) insert(e nsecEntry, now time.Time) {
	i := z.search(e.nsec.Hdr.Name)
	if i >= 0 && dnssec.EqualNames(z.entries[i].nsec.Hdr.Name, e.nsec.Hdr.Name) {
		z.entries[i] = e
		return
	}
	if len(z.entries) >= maxNSECPerZone {
		live := z.entries[:0]
		for _, x := range z.entries {
			if now.Before(x.set.expire) {
				live = append(live, x)
			}
		}
		z.entries = live
		if len(z.entries) >= maxNSECPerZone {
			z.entries = z.entries[1:]
		}
		i = z.search(e.nsec.Hdr.Name)
	}
	z.entries = append(z.entries, nsecEntry{})
	copy(z.entries[i+2:], z.entries[i+1:])
	z.entries[i+1] = e
}

func (z *nsecZone) prev(name string, now time.Time) *nsecEntry {
	i := z.search(name)
	if i < 0 || !now.Before(z.entries[i].set.expire) {
		return nil
	}
	e := z.entries[i]
	return &e
}

func (c *cache) nsecZoneFor(name string) *nsecZone {
	for n := name; ; n = dnssec.ParentName(n) {
		if z, ok := c.nsecs.Get(n); ok {
			return z
		}
		if n == "." {
			return nil
		}
	}
}

func sigExpiry(sigs []*dns.RRSIG, now time.Time) (time.Time, bool) {
	var out time.Time
	found := false
	t := uint32(now.Unix())
	for _, sig := range sigs {
		d := int32(sig.Expiration - t)
		if d <= 0 {
			continue
		}
		e := now.Add(time.Duration(d) * time.Second)
		if !found || e.Before(out) {
			out, found = e, true
		}
	}
	return out, found
}

func prefetchAt(now, expire time.Time) time.Time {
	return expire.Add(-expire.Sub(now) / 10)
}

func setKey(name string, t uint16) string {
	return name + "|" + strconv.Itoa(int(t))
}

func nxKey(name string) string {
	return name + "|nx"
}

func (c *cache) getSet(name string, t uint16, minTrust trustLevel) *rrset {
	k := setKey(name, t)
	s, ok := c.sets.Get(k)
	if !ok {
		return nil
	}
	if !c.now().Before(s.expire) {
		c.sets.Del(k)
		return nil
	}
	if s.trust < minTrust {
		return nil
	}
	return s
}

func (c *cache) putSet(s *rrset) {
	k := setKey(s.name, s.rtype)
	if old, ok := c.sets.Get(k); ok && c.now().Before(old.expire) && old.trust > s.trust {
		return
	}
	c.sets.Add(k, s)
}

func (c *cache) delSet(name string, t uint16) {
	c.sets.Del(setKey(name, t))
}

func (c *cache) getNeg(name string, t uint16) *negative {
	for _, k := range []string{nxKey(name), setKey(name, t)} {
		n, ok := c.negs.Get(k)
		if !ok {
			continue
		}
		if !c.now().Before(n.expire) {
			c.negs.Del(k)
			continue
		}
		return n
	}
	return nil
}

func (c *cache) putNeg(n *negative) {
	k := setKey(n.name, n.qtype)
	if n.rcode == dns.RcodeNameError {
		k = nxKey(n.name)
	}
	c.negs.Add(k, n)
}

func (c *cache) delNeg(n *negative) {
	c.negs.Del(setKey(n.name, n.qtype))
	c.negs.Del(nxKey(n.name))
}

func (c *cache) getBogus(name string, t uint16) *bogusEntry {
	k := setKey(name, t)
	b, ok := c.bogus.Get(k)
	if !ok {
		return nil
	}
	if !c.now().Before(b.expire) {
		c.bogus.Del(k)
		return nil
	}
	return b
}

func (c *cache) putBogus(name string, t uint16, ede uint16) {
	c.bogus.Add(setKey(name, t), &bogusEntry{ede: ede, expire: c.now().Add(bogusTTL)})
}

func (c *cache) getKeys(zone string) *zoneSec {
	z, ok := c.keys.Get(zone)
	if !ok {
		return nil
	}
	if !c.now().Before(z.expire) {
		c.keys.Del(zone)
		return nil
	}
	return z
}

func (c *cache) putKeys(name string, z *zoneSec) {
	c.keys.Add(name, z)
}

func (c *cache) delKeys(name string) {
	c.keys.Del(name)
}

func (c *cache) len() int {
	return c.sets.Len() + c.negs.Len()
}

func capTTL(ttl uint32, max time.Duration) time.Duration {
	d := time.Duration(ttl) * time.Second
	if d > max {
		d = max
	}
	return d
}

func (c *cache) remaining(expire time.Time) uint32 {
	d := expire.Sub(c.now())
	if d <= 0 {
		return 0
	}
	return uint32((d + time.Second - 1) / time.Second)
}
