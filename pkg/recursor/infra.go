package recursor

import (
	"math/rand/v2"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
)

const (
	unknownRTT        = 376 * time.Millisecond
	unknownTimeout    = 600 * time.Millisecond
	minTimeout        = 300 * time.Millisecond
	maxTimeout        = 2 * time.Second
	rttBand           = 400 * time.Millisecond
	lameDuration      = 15 * time.Minute
	ednsDuration      = 15 * time.Minute
	maxEDNSZones      = 64
	backoffAfterFails = 4
	backoffDuration   = time.Minute
	dotOKDuration     = 3 * 24 * time.Hour
	dotFailDuration   = 24 * time.Hour
	infraSize         = 8192
)

type dotState uint8

const (
	dotUnknown dotState = iota
	dotOK
	dotFailed
)

type ednsState struct {
	works bool
	until time.Time
}

type serverInfo struct {
	mu           sync.Mutex
	samples      int
	srtt         time.Duration
	rttvar       time.Duration
	rto          time.Duration
	fails        int
	backoffUntil time.Time
	edns         map[string]ednsState
	noECS        bool
	lame         map[string]time.Time
	dot          dotState
	dotUntil     time.Time
	dotProbing   bool
}

func (s *serverInfo) calcRTO() time.Duration {
	return clampDuration(s.srtt+4*s.rttvar, minTimeout, maxTimeout)
}

func (s *serverInfo) selectionRTT() time.Duration {
	if s.samples == 0 {
		if s.rto > unknownTimeout {
			return s.rto
		}
		return unknownRTT
	}
	if s.rto > s.calcRTO() {
		return s.rto
	}
	return s.srtt + 4*s.rttvar
}

type infra struct {
	now     func() time.Time
	servers *concurrent_lru.ConcurrentLRU[netip.Addr, *serverInfo]
	mu      sync.Mutex
}

func newInfra(now func() time.Time) *infra {
	return &infra{
		now:     now,
		servers: concurrent_lru.NewConecurrentLRU[netip.Addr, *serverInfo](infraSize, nil),
	}
}

func (in *infra) get(addr netip.Addr) *serverInfo {
	in.mu.Lock()
	defer in.mu.Unlock()
	s, ok := in.servers.Get(addr)
	if !ok {
		s = &serverInfo{}
		in.servers.Add(addr, s)
	}
	return s
}

func (in *infra) timeout(addr netip.Addr) time.Duration {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rto > 0 {
		return s.rto
	}
	return unknownTimeout
}

func (in *infra) success(addr netip.Addr, rtt time.Duration) {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.samples == 0 {
		s.srtt = rtt
		s.rttvar = rtt / 2
	} else {
		delta := rtt - s.srtt
		s.srtt += delta / 8
		if delta < 0 {
			delta = -delta
		}
		s.rttvar += (delta - s.rttvar) / 4
	}
	s.samples++
	s.rto = s.calcRTO()
	s.fails = 0
	s.backoffUntil = time.Time{}
}

func (in *infra) failure(addr netip.Addr, timeout time.Duration) {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rto == 0 || s.rto >= timeout {
		s.rto = min(2*timeout, maxTimeout)
	}
	s.fails++
	if s.fails >= backoffAfterFails {
		s.backoffUntil = in.now().Add(backoffDuration)
	}
}

func (in *infra) markLame(addr netip.Addr, zone string) {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lame == nil {
		s.lame = make(map[string]time.Time)
	}
	s.lame[zone] = in.now().Add(lameDuration)
}

func (in *infra) noEDNS(addr netip.Addr, zone string) bool {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.edns[zone]
	return ok && !e.works && in.now().Before(e.until)
}

func (in *infra) setEDNS(addr netip.Addr, zone string, works bool) {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := in.now()
	if e, ok := s.edns[zone]; ok && now.Before(e.until) && e.works {
		return
	}
	if s.edns == nil {
		s.edns = make(map[string]ednsState)
	}
	if len(s.edns) >= maxEDNSZones {
		for z, e := range s.edns {
			if !now.Before(e.until) {
				delete(s.edns, z)
			}
		}
		if len(s.edns) >= maxEDNSZones {
			return
		}
	}
	s.edns[zone] = ednsState{works: works, until: now.Add(ednsDuration)}
}

func (in *infra) setNoECS(addr netip.Addr) {
	s := in.get(addr)
	s.mu.Lock()
	s.noECS = true
	s.mu.Unlock()
}

func (in *infra) noECS(addr netip.Addr) bool {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.noECS
}

func (in *infra) dotStatus(addr netip.Addr) dotState {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dot != dotUnknown && !in.now().Before(s.dotUntil) {
		s.dot = dotUnknown
	}
	return s.dot
}

func (in *infra) beginProbe(addr netip.Addr) bool {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dot != dotUnknown && !in.now().Before(s.dotUntil) {
		s.dot = dotUnknown
	}
	if s.dot != dotUnknown || s.dotProbing {
		return false
	}
	s.dotProbing = true
	return true
}

func (in *infra) endProbe(addr netip.Addr) {
	s := in.get(addr)
	s.mu.Lock()
	s.dotProbing = false
	s.mu.Unlock()
}

func (in *infra) setDoT(addr netip.Addr, ok bool) {
	s := in.get(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dotProbing = false
	if ok {
		s.dot = dotOK
		s.dotUntil = in.now().Add(dotOKDuration)
	} else {
		s.dot = dotFailed
		s.dotUntil = in.now().Add(dotFailDuration)
	}
}

type candidate struct {
	addr      netip.Addr
	rtt       time.Duration
	penalized bool
}

func (in *infra) pick(addrs []netip.Addr, zone string, avoid map[netip.Addr]bool, n int) []netip.Addr {
	now := in.now()
	cands := make([]candidate, 0, len(addrs))
	for _, a := range addrs {
		s := in.get(a)
		s.mu.Lock()
		c := candidate{addr: a, rtt: s.selectionRTT()}
		if now.Before(s.backoffUntil) {
			c.penalized = true
		}
		if t, ok := s.lame[zone]; ok && now.Before(t) {
			c.penalized = true
		}
		s.mu.Unlock()
		if avoid[a] {
			c.penalized = true
		}
		cands = append(cands, c)
	}
	rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].penalized != cands[j].penalized {
			return !cands[i].penalized
		}
		return cands[i].rtt < cands[j].rtt
	})
	out := make([]netip.Addr, 0, n)
	for len(cands) > 0 && len(out) < n {
		best := cands[0]
		band := 1
		for band < len(cands) && cands[band].penalized == best.penalized && cands[band].rtt-best.rtt <= rttBand {
			band++
		}
		i := rand.IntN(band)
		out = append(out, cands[i].addr)
		cands = append(cands[:i], cands[i+1:]...)
	}
	return out
}
