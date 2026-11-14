package dnssec

import (
	"bytes"
	"strings"

	"github.com/miekg/dns"
)

func wireLabels(name string) [][]byte {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		var ls [][]byte
		for _, l := range dns.SplitDomainName(name) {
			ls = append(ls, []byte(strings.ToLower(l)))
		}
		return ls
	}
	var ls [][]byte
	for off := 0; off < n; {
		l := int(buf[off])
		if l == 0 || off+1+l > n {
			break
		}
		lab := buf[off+1 : off+1+l]
		for i, c := range lab {
			if c >= 'A' && c <= 'Z' {
				lab[i] = c + 'a' - 'A'
			}
		}
		ls = append(ls, lab)
		off += 1 + l
	}
	return ls
}

func CompareNames(a, b string) int {
	la, lb := wireLabels(a), wireLabels(b)
	i, j := len(la)-1, len(lb)-1
	for ; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	switch {
	case i >= 0:
		return 1
	case j >= 0:
		return -1
	}
	return 0
}

func EqualNames(a, b string) bool {
	return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b))
}

func ParentName(name string) string {
	if name == "." || name == "" {
		return "."
	}
	off, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[off:]
}

func CommonAncestor(a, b string) string {
	n := dns.CompareDomainName(a, b)
	if n == 0 {
		return "."
	}
	idx := dns.Split(a)
	return a[idx[len(idx)-n]:]
}

func IsStrictSubDomain(parent, child string) bool {
	return dns.IsSubDomain(parent, child) && !EqualNames(parent, child)
}

func NextCloser(name, ancestor string) string {
	want := dns.CountLabel(ancestor) + 1
	idx := dns.Split(name)
	if want > len(idx) {
		return name
	}
	return name[idx[len(idx)-want]:]
}

func typeInBitmap(bm []uint16, t uint16) bool {
	for _, x := range bm {
		if x == t {
			return true
		}
	}
	return false
}

func isDelegationBitmap(bm []uint16) bool {
	return typeInBitmap(bm, dns.TypeNS) && !typeInBitmap(bm, dns.TypeSOA)
}
