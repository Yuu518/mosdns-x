package recursor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	addHoldDown      = 30 * 24 * time.Hour
	removeHoldDown   = 90 * 24 * time.Hour
	autoTrustRefresh = 12 * time.Hour
)

type taState uint8

const (
	taAddPend taState = iota
	taValid
	taMissing
	taRevoked
)

var taStateNames = [...]string{"addpend", "valid", "missing", "revoked"}

func (s taState) String() string {
	return taStateNames[s]
}

func parseTAState(s string) (taState, bool) {
	for i, n := range taStateNames {
		if n == s {
			return taState(i), true
		}
	}
	return 0, false
}

type taKey struct {
	key     *dns.DNSKEY
	state   taState
	first   time.Time
	changed time.Time
}

type autoTrust struct {
	file    string
	logger  *zap.Logger
	initial []*dns.DS
	mu      sync.Mutex
	keys    []*taKey
}

func newAutoTrust(file string, initial []*dns.DS, logger *zap.Logger) (*autoTrust, error) {
	a := &autoTrust{file: file, logger: logger, initial: initial}
	raw, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return a, nil
		}
		return nil, err
	}
	keys, err := parseAutoTrust(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust anchor state %s, %w", file, err)
	}
	a.keys = keys
	return a, nil
}

func parseAutoTrust(raw []byte) ([]*taKey, error) {
	var out []*taKey
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, " ", 4)
		if len(f) != 4 {
			return nil, fmt.Errorf("line %d: malformed", i+1)
		}
		state, ok := parseTAState(f[0])
		if !ok {
			return nil, fmt.Errorf("line %d: unknown state %q", i+1, f[0])
		}
		first, err1 := strconv.ParseInt(f[1], 10, 64)
		changed, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("line %d: bad timestamp", i+1)
		}
		rr, err := dns.NewRR(f[3])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		k, ok := rr.(*dns.DNSKEY)
		if !ok || dns.CanonicalName(k.Hdr.Name) != "." {
			return nil, fmt.Errorf("line %d: not a root dnskey", i+1)
		}
		out = append(out, &taKey{key: k, state: state, first: time.Unix(first, 0), changed: time.Unix(changed, 0)})
	}
	return out, nil
}

func (a *autoTrust) anchors() []*dns.DS {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*dns.DS
	for _, e := range a.keys {
		if e.state == taValid || e.state == taMissing {
			if ds := e.key.ToDS(dns.SHA256); ds != nil {
				out = append(out, ds)
			}
		}
	}
	if len(out) == 0 {
		return a.initial
	}
	return out
}

func (a *autoTrust) trusted() bool {
	for _, e := range a.keys {
		if e.state == taValid || e.state == taMissing {
			return true
		}
	}
	return false
}

func sameKey(x, y *dns.DNSKEY) bool {
	return x.Algorithm == y.Algorithm && x.Protocol == y.Protocol &&
		x.Flags&^dns.REVOKE == y.Flags&^dns.REVOKE && x.PublicKey == y.PublicKey
}

func (a *autoTrust) find(k *dns.DNSKEY) *taKey {
	for _, e := range a.keys {
		if sameKey(e.key, k) {
			return e
		}
	}
	return nil
}

func matchesDS(k *dns.DNSKEY, dsSet []*dns.DS) bool {
	for _, ds := range dsSet {
		if ds.KeyTag != k.KeyTag() || ds.Algorithm != k.Algorithm {
			continue
		}
		if d := k.ToDS(ds.DigestType); d != nil && strings.EqualFold(d.Digest, ds.Digest) {
			return true
		}
	}
	return false
}

func selfSigned(k *dns.DNSKEY, keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) bool {
	rrset := make([]dns.RR, len(keys))
	for i, x := range keys {
		rrset[i] = x
	}
	for _, sig := range sigs {
		if sig.KeyTag != k.KeyTag() || sig.Algorithm != k.Algorithm || !sig.ValidityPeriod(now) {
			continue
		}
		if sig.Verify(k, rrset) == nil {
			return true
		}
	}
	return false
}

func newTAKey(k *dns.DNSKEY, state taState, now time.Time) *taKey {
	c := dns.Copy(k).(*dns.DNSKEY)
	c.Hdr.Name = "."
	return &taKey{key: c, state: state, first: now, changed: now}
}

func (a *autoTrust) update(keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	if !a.trusted() {
		for _, k := range keys {
			if k.Flags&dns.SEP != 0 && k.Flags&dns.REVOKE == 0 && matchesDS(k, a.initial) {
				if e := a.find(k); e != nil {
					e.state, e.changed = taValid, now
				} else {
					a.keys = append(a.keys, newTAKey(k, taValid, now))
				}
				changed = true
			}
		}
	}
	present := make(map[*taKey]bool)
	for _, k := range keys {
		if k.Flags&dns.SEP == 0 || k.Protocol != 3 {
			continue
		}
		e := a.find(k)
		if k.Flags&dns.REVOKE != 0 {
			if e == nil {
				continue
			}
			present[e] = true
			if e.state != taRevoked && selfSigned(k, keys, sigs, now) {
				e.state, e.changed = taRevoked, now
				changed = true
				a.logger.Warn("root trust anchor revoked", zap.Uint16("keytag", k.KeyTag()))
			}
			continue
		}
		if e == nil {
			e = newTAKey(k, taAddPend, now)
			a.keys = append(a.keys, e)
			present[e] = true
			changed = true
			a.logger.Info("new root trust anchor pending", zap.Uint16("keytag", k.KeyTag()))
			continue
		}
		present[e] = true
		switch e.state {
		case taAddPend:
			if !now.Before(e.first.Add(addHoldDown)) {
				e.state, e.changed = taValid, now
				changed = true
				a.logger.Info("root trust anchor accepted", zap.Uint16("keytag", k.KeyTag()))
			}
		case taMissing:
			e.state, e.changed = taValid, now
			changed = true
		}
	}
	kept := a.keys[:0]
	for _, e := range a.keys {
		if !present[e] {
			switch e.state {
			case taAddPend:
				changed = true
				continue
			case taValid:
				e.state, e.changed = taMissing, now
				changed = true
			case taRevoked:
				if !now.Before(e.changed.Add(removeHoldDown)) {
					changed = true
					continue
				}
			}
		}
		kept = append(kept, e)
	}
	a.keys = kept
	if changed {
		if err := a.save(); err != nil {
			a.logger.Warn("failed to save trust anchor state", zap.String("file", a.file), zap.Error(err))
		}
	}
}

func (a *autoTrust) save() error {
	var b bytes.Buffer
	for _, e := range a.keys {
		fmt.Fprintf(&b, "%s %d %d %s\n", e.state, e.first.Unix(), e.changed.Unix(), e.key.String())
	}
	return writeFileAtomic(a.file, b.Bytes())
}

func (r *Resolver) startAutoTrust() {
	interval := r.opts.autoTrustInterval
	if interval <= 0 {
		interval = autoTrustRefresh
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-t.C:
				r.refreshRootKeys()
			}
		}
	}()
}

func (r *Resolver) refreshRootKeys() {
	defer r.recoverPanic(nil)
	ctx, cancel := context.WithTimeout(r.ctx, sharedTimeout)
	defer cancel()
	r.cache.delSet(".", dns.TypeDNSKEY)
	r.cache.delKeys(".")
	st := newReqState(true, nil, nil)
	if _, err := r.zoneSec(ctx, st, "."); err != nil {
		r.logger.Debug("root dnskey refresh failed", zap.Error(err))
	}
}
