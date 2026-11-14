package dnssec

import (
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoSignature  = errors.New("dnssec: no signature")
	ErrNoKey        = errors.New("dnssec: no matching key")
	ErrExpired      = errors.New("dnssec: signature expired")
	ErrNotYetValid  = errors.New("dnssec: signature not yet valid")
	ErrBadSignature = errors.New("dnssec: bad signature")
	ErrBudget       = errors.New("dnssec: validation budget exhausted")
	ErrUnsupported  = errors.New("dnssec: unsupported algorithm or digest")
	ErrDSMismatch   = errors.New("dnssec: no key matches the ds set")
)

const maxKeysPerTag = 4

type Budget struct {
	left atomic.Int64
}

func NewBudget(n int) *Budget {
	b := &Budget{}
	b.left.Store(int64(n))
	return b
}

func (b *Budget) available() bool {
	return b == nil || b.left.Load() > 0
}

func (b *Budget) fail() {
	if b != nil {
		b.left.Add(-1)
	}
}

func SupportedAlgorithm(alg uint8) bool {
	switch alg {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512,
		dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}

func SupportedDigest(d uint8) bool {
	switch d {
	case dns.SHA1, dns.SHA256, dns.SHA384:
		return true
	}
	return false
}

func usableKey(k *dns.DNSKEY) bool {
	return k.Protocol == 3 && k.Flags&dns.ZONE != 0 && k.Flags&dns.REVOKE == 0
}

func matchingKeys(sig *dns.RRSIG, keys []*dns.DNSKEY) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, k := range keys {
		if k.Algorithm != sig.Algorithm || !usableKey(k) || !EqualNames(k.Hdr.Name, sig.SignerName) {
			continue
		}
		if k.KeyTag() != sig.KeyTag {
			continue
		}
		out = append(out, k)
		if len(out) >= maxKeysPerTag {
			break
		}
	}
	return out
}

func signatureTimeErr(sig *dns.RRSIG, now time.Time) error {
	if sig.ValidityPeriod(now) {
		return nil
	}
	t := uint32(now.Unix())
	if int32(sig.Inception-t) > 0 {
		return ErrNotYetValid
	}
	return ErrExpired
}

func VerifyRRset(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time, b *Budget) (*dns.RRSIG, error) {
	if len(rrset) == 0 {
		return nil, ErrBadSignature
	}
	if len(sigs) == 0 {
		return nil, ErrNoSignature
	}
	h := rrset[0].Header()
	var lastErr error = ErrNoSignature
	sawSupported := false
	for _, sig := range sigs {
		if sig.TypeCovered != h.Rrtype || !EqualNames(sig.Hdr.Name, h.Name) {
			continue
		}
		if !SupportedAlgorithm(sig.Algorithm) {
			continue
		}
		sawSupported = true
		if !dns.IsSubDomain(sig.SignerName, h.Name) || int(sig.Labels) > dns.CountLabel(h.Name) {
			lastErr = ErrBadSignature
			continue
		}
		cands := matchingKeys(sig, keys)
		if len(cands) == 0 {
			if lastErr == ErrNoSignature {
				lastErr = ErrNoKey
			}
			continue
		}
		if err := signatureTimeErr(sig, now); err != nil {
			lastErr = err
			continue
		}
		for _, k := range cands {
			if !b.available() {
				return nil, ErrBudget
			}
			if err := sig.Verify(k, rrset); err == nil {
				return sig, nil
			}
			b.fail()
			lastErr = ErrBadSignature
		}
	}
	if !sawSupported {
		return nil, ErrUnsupported
	}
	return nil, lastErr
}

func filterDS(dsSet []*dns.DS) []*dns.DS {
	var usable []*dns.DS
	strong := false
	for _, ds := range dsSet {
		if SupportedAlgorithm(ds.Algorithm) && SupportedDigest(ds.DigestType) {
			usable = append(usable, ds)
			if ds.DigestType != dns.SHA1 {
				strong = true
			}
		}
	}
	if !strong {
		return usable
	}
	out := usable[:0]
	for _, ds := range usable {
		if ds.DigestType != dns.SHA1 {
			out = append(out, ds)
		}
	}
	return out
}

func HasSupportedDS(dsSet []*dns.DS) bool {
	return len(filterDS(dsSet)) > 0
}

func VerifyDNSKEYs(keys []*dns.DNSKEY, sigs []*dns.RRSIG, dsSet []*dns.DS, now time.Time, b *Budget) error {
	usable := filterDS(dsSet)
	if len(usable) == 0 {
		return ErrUnsupported
	}
	if len(keys) == 0 {
		return ErrNoKey
	}
	var matched []*dns.DNSKEY
	for _, ds := range usable {
		for _, k := range keys {
			if k.Algorithm != ds.Algorithm || !usableKey(k) || !EqualNames(k.Hdr.Name, ds.Hdr.Name) {
				continue
			}
			if k.KeyTag() != ds.KeyTag {
				continue
			}
			d := k.ToDS(ds.DigestType)
			if d == nil || !strings.EqualFold(d.Digest, ds.Digest) {
				continue
			}
			dup := false
			for _, m := range matched {
				if m == k {
					dup = true
					break
				}
			}
			if !dup {
				matched = append(matched, k)
			}
		}
	}
	if len(matched) == 0 {
		return ErrDSMismatch
	}
	rrset := make([]dns.RR, len(keys))
	for i, k := range keys {
		rrset[i] = k
	}
	_, err := VerifyRRset(rrset, sigs, matched, now, b)
	return err
}

func KeysToDS(keys []*dns.DNSKEY) []*dns.DS {
	var out []*dns.DS
	for _, k := range keys {
		if ds := k.ToDS(dns.SHA256); ds != nil {
			out = append(out, ds)
		}
	}
	return out
}
