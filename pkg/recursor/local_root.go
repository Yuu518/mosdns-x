package recursor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnssec"
	D "github.com/pmkol/mosdns-x/pkg/upstream/dialer"
)

const (
	DefaultLocalRootSource = "https://www.internic.net/domain/root.zone"
	localRootRefresh       = 12 * time.Hour
	localRootMaxSize       = 16 << 20
	localRootHTTPTimeout   = 2 * time.Minute
)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type rootZone struct {
	serial  uint32
	expire  time.Duration
	fetched time.Time
	sets    map[string]map[uint16][]dns.RR
	sigs    map[string]map[uint16][]*dns.RRSIG
	nsecs   []*dns.NSEC
	count   int
}

func (z *rootZone) get(name string, t uint16) []dns.RR {
	return z.sets[name][t]
}

type localRoot struct {
	r        *Resolver
	source   string
	isURL    bool
	file     string
	interval time.Duration
	client   httpDoer

	mu      sync.RWMutex
	data    *rootZone
	lastMod string
	srcMod  time.Time
}

func newLocalRoot(r *Resolver) *localRoot {
	l := &localRoot{
		r:        r,
		source:   r.opts.LocalRootSource,
		file:     r.opts.LocalRootFile,
		interval: r.opts.localRootInterval,
		client:   r.opts.localRootHTTPClient,
	}
	if l.source == "" {
		l.source = DefaultLocalRootSource
	}
	l.isURL = strings.HasPrefix(l.source, "http://") || strings.HasPrefix(l.source, "https://")
	if l.interval <= 0 {
		l.interval = localRootRefresh
	}
	if l.client == nil {
		l.client = &http.Client{
			Timeout: localRootHTTPTimeout,
			Transport: &http.Transport{
				DialContext:         l.dial,
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: 30 * time.Second,
				IdleConnTimeout:     30 * time.Second,
			},
		}
	}
	return l
}

func (l *localRoot) start() {
	l.r.wg.Add(1)
	go func() {
		defer l.r.wg.Done()
		if l.file != "" && l.isURL {
			if err := l.loadPersisted(); err != nil && !errors.Is(err, os.ErrNotExist) {
				l.r.logger.Warn("ignoring persisted root zone", zap.String("file", l.file), zap.Error(err))
			}
		}
		l.refresh()
		t := time.NewTicker(l.interval)
		defer t.Stop()
		for {
			select {
			case <-l.r.ctx.Done():
				return
			case <-t.C:
				l.refresh()
			}
		}
	}()
}

func (l *localRoot) current() *rootZone {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.data
}

func (l *localRoot) active() bool {
	z := l.current()
	return z != nil && l.r.now().Before(z.fetched.Add(z.expire))
}

func (l *localRoot) serial() uint32 {
	if z := l.current(); z != nil {
		return z.serial
	}
	return 0
}

func (l *localRoot) loadPersisted() error {
	st, err := os.Stat(l.file)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(l.file)
	if err != nil {
		return err
	}
	z, err := l.r.parseRootZone(raw)
	if err != nil {
		return err
	}
	z.fetched = st.ModTime()
	if !l.r.now().Before(z.fetched.Add(z.expire)) {
		return errors.New("persisted root zone has expired")
	}
	l.mu.Lock()
	l.data = z
	l.lastMod = st.ModTime().UTC().Format(http.TimeFormat)
	l.mu.Unlock()
	l.r.logger.Info("local root zone loaded", zap.String("file", l.file), zap.Uint32("serial", z.serial), zap.Int("records", z.count))
	return nil
}

func (l *localRoot) refresh() {
	defer l.r.recoverPanic(nil)
	raw, mod, err := l.fetch()
	if err != nil {
		l.r.logger.Warn("failed to refresh local root zone", zap.String("source", l.source), zap.Error(err))
		l.warnIfInactive()
		return
	}
	if raw == nil {
		l.warnIfInactive()
		return
	}
	z, err := l.r.parseRootZone(raw)
	if err != nil {
		l.r.logger.Warn("rejected root zone data", zap.String("source", l.source), zap.Error(err))
		l.warnIfInactive()
		return
	}
	z.fetched = l.r.now()
	if !l.isURL && !mod.IsZero() {
		z.fetched = mod
	}
	l.mu.Lock()
	old := l.data
	if old != nil && !serialNewer(z.serial, old.serial) {
		l.mu.Unlock()
		if z.serial != old.serial {
			l.r.logger.Warn("rejected root zone with older serial", zap.Uint32("serial", z.serial), zap.Uint32("current", old.serial))
		}
		l.warnIfInactive()
		return
	}
	l.data = z
	if l.isURL {
		if !mod.IsZero() {
			l.lastMod = mod.UTC().Format(http.TimeFormat)
		}
	} else {
		l.srcMod = mod
	}
	l.mu.Unlock()
	l.r.logger.Info("local root zone loaded", zap.String("source", l.source), zap.Uint32("serial", z.serial), zap.Int("records", z.count))
	if l.isURL && l.file != "" {
		if err := writeFileAtomic(l.file, raw); err != nil {
			l.r.logger.Warn("failed to persist root zone", zap.String("file", l.file), zap.Error(err))
		}
	}
}

func (l *localRoot) warnIfInactive() {
	if !l.active() {
		l.r.logger.Warn("local root zone unavailable, using root servers")
	}
}

func serialNewer(a, b uint32) bool {
	return a != b && int32(a-b) > 0
}

func (l *localRoot) fetch() ([]byte, time.Time, error) {
	if !l.isURL {
		st, err := os.Stat(l.source)
		if err != nil {
			return nil, time.Time{}, err
		}
		l.mu.RLock()
		same := l.data != nil && st.ModTime().Equal(l.srcMod)
		l.mu.RUnlock()
		if same {
			return nil, time.Time{}, nil
		}
		raw, err := os.ReadFile(l.source)
		return raw, st.ModTime(), err
	}
	ctx, cancel := context.WithTimeout(l.r.ctx, localRootHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.source, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	l.mu.RLock()
	if l.data != nil && l.lastMod != "" {
		req.Header.Set("If-Modified-Since", l.lastMod)
	}
	l.mu.RUnlock()
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, time.Time{}, nil
	case http.StatusOK:
	default:
		return nil, time.Time{}, fmt.Errorf("unexpected http status %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, localRootMaxSize+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(raw) > localRootMaxSize {
		return nil, time.Time{}, errors.New("root zone file too large")
	}
	mod, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return raw, mod, nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (r *Resolver) parseRootZone(raw []byte) (*rootZone, error) {
	rrs, err := ParseRRs(bytes.NewReader(raw), ".")
	if err != nil {
		return nil, err
	}
	soa := dnssec.ZoneSOA(rrs, ".")
	if soa == nil {
		return nil, dnssec.ErrZONEMDNoSOA
	}
	z := &rootZone{
		serial: soa.Serial,
		expire: time.Duration(soa.Expire) * time.Second,
		sets:   make(map[string]map[uint16][]dns.RR),
		sigs:   make(map[string]map[uint16][]*dns.RRSIG),
		count:  len(rrs),
	}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Class != dns.ClassINET {
			return nil, fmt.Errorf("unexpected class in %s", rr.String())
		}
		h.Name = dns.CanonicalName(h.Name)
		if sig, ok := rr.(*dns.RRSIG); ok {
			sig.SignerName = dns.CanonicalName(sig.SignerName)
			m := z.sigs[h.Name]
			if m == nil {
				m = make(map[uint16][]*dns.RRSIG)
				z.sigs[h.Name] = m
			}
			m[sig.TypeCovered] = append(m[sig.TypeCovered], sig)
			continue
		}
		m := z.sets[h.Name]
		if m == nil {
			m = make(map[uint16][]dns.RR)
			z.sets[h.Name] = m
		}
		m[h.Rrtype] = append(m[h.Rrtype], rr)
		if n, ok := rr.(*dns.NSEC); ok {
			z.nsecs = append(z.nsecs, n)
		}
	}
	sort.Slice(z.nsecs, func(i, j int) bool { return dnssec.CompareNames(z.nsecs[i].Hdr.Name, z.nsecs[j].Hdr.Name) < 0 })

	now := r.now()
	var keys []*dns.DNSKEY
	for _, rr := range z.get(".", dns.TypeDNSKEY) {
		keys = append(keys, rr.(*dns.DNSKEY))
	}
	if err := dnssec.VerifyDNSKEYs(keys, z.sigs["."][dns.TypeDNSKEY], r.trustAnchors(), now, nil); err != nil {
		return nil, fmt.Errorf("root dnskey validation failed: %w", err)
	}
	mds := z.get(".", dns.TypeZONEMD)
	if len(mds) == 0 {
		return nil, dnssec.ErrZONEMDMissing
	}
	if _, err := dnssec.VerifyRRset(mds, z.sigs["."][dns.TypeZONEMD], keys, now, nil); err != nil {
		return nil, fmt.Errorf("zonemd signature validation failed: %w", err)
	}
	if err := dnssec.VerifyZONEMD(rrs, "."); err != nil {
		return nil, err
	}
	return z, nil
}

func (l *localRoot) answer(qn string, qt uint16) *dns.Msg {
	if !l.active() {
		return nil
	}
	z := l.current()
	m := new(dns.Msg)
	m.Response = true
	m.Authoritative = true
	m.Question = []dns.Question{{Name: qn, Qtype: qt, Qclass: dns.ClassINET}}
	add := func(dst *[]dns.RR, name string, t uint16) bool {
		rrs := z.get(name, t)
		if len(rrs) == 0 {
			return false
		}
		for _, rr := range rrs {
			*dst = append(*dst, dns.Copy(rr))
		}
		for _, s := range z.sigs[name][t] {
			*dst = append(*dst, dns.Copy(s))
		}
		return true
	}
	addNSEC := func(dst *[]dns.RR, n *dns.NSEC) {
		for _, x := range *dst {
			if x.Header().Rrtype == dns.TypeNSEC && x.Header().Name == n.Hdr.Name {
				return
			}
		}
		add(dst, n.Hdr.Name, dns.TypeNSEC)
	}
	noData := func(name string) {
		add(&m.Ns, ".", dns.TypeSOA)
		add(&m.Ns, name, dns.TypeNSEC)
	}

	if qn == "." {
		if !add(&m.Answer, ".", qt) {
			noData(".")
		}
		return m
	}
	idx := dns.Split(qn)
	tld := qn[idx[len(idx)-1]:]
	if len(z.get(tld, dns.TypeNS)) > 0 {
		if qn == tld && qt == dns.TypeDS {
			if !add(&m.Answer, tld, dns.TypeDS) {
				noData(tld)
			}
			return m
		}
		m.Authoritative = false
		add(&m.Ns, tld, dns.TypeNS)
		if !add(&m.Ns, tld, dns.TypeDS) {
			add(&m.Ns, tld, dns.TypeNSEC)
		}
		for _, rr := range z.get(tld, dns.TypeNS) {
			host := dns.CanonicalName(rr.(*dns.NS).Ns)
			for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
				for _, g := range z.get(host, t) {
					m.Extra = append(m.Extra, dns.Copy(g))
				}
			}
		}
		return m
	}
	m.Rcode = dns.RcodeNameError
	add(&m.Ns, ".", dns.TypeSOA)
	if n := z.cover(tld); n != nil {
		addNSEC(&m.Ns, n)
	}
	if n := z.cover("*."); n != nil {
		addNSEC(&m.Ns, n)
	}
	return m
}

func (z *rootZone) cover(name string) *dns.NSEC {
	if len(z.nsecs) == 0 {
		return nil
	}
	i := sort.Search(len(z.nsecs), func(i int) bool {
		return dnssec.CompareNames(z.nsecs[i].Hdr.Name, name) > 0
	}) - 1
	if i < 0 {
		i = len(z.nsecs) - 1
	}
	return z.nsecs[i]
}

func (l *localRoot) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := l.r.opts.Dialer
	if d == nil {
		d, err = D.NewDialer(D.DialerOpts{Dialer: &net.Dialer{}})
		if err != nil {
			return nil, err
		}
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = l.r.lookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	var lastErr error = fmt.Errorf("no address for %s", host)
	for _, a := range addrs {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *Resolver) lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	name := dns.CanonicalName(host)
	var out []netip.Addr
	var lastErr error
	for _, t := range r.addrTypes() {
		st := newReqState(false, nil, nil)
		ch, err := r.resolveChain(ctx, st, name, t, false)
		if err != nil {
			lastErr = err
			continue
		}
		for _, s := range ch.sets {
			if s.rtype == t {
				out = append(out, addrsOf(s)...)
			}
		}
	}
	if len(out) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no address for %s", host)
		}
		return nil, lastErr
	}
	return out, nil
}
