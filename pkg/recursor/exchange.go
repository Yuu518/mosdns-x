package recursor

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	D "github.com/pmkol/mosdns-x/pkg/upstream/dialer"
	"github.com/pmkol/mosdns-x/pkg/upstream/transport"
)

type proto uint8

const (
	protoUDP proto = iota
	protoTCP
	protoDoT
)

const (
	dnsPort          = 53
	dotPort          = 853
	dotTransportsMax = 256
	dotIdleTimeout   = 10 * time.Second
	probeTimeout     = 4 * time.Second
)

var errMismatch = errors.New("recursor: response does not match the query")

type exchanger interface {
	exchange(ctx context.Context, addr netip.Addr, q *dns.Msg, p proto) (*dns.Msg, error)
	probeDoT(ctx context.Context, addr netip.Addr) error
	close() error
}

type netExchanger struct {
	dialer  D.Dialer
	logger  *zap.Logger
	port    uint16
	dotPort uint16

	mu   sync.Mutex
	dots *concurrent_lru.ConcurrentLRU[netip.Addr, *transport.Transport]
}

func newNetExchanger(d D.Dialer, logger *zap.Logger) *netExchanger {
	return &netExchanger{
		dialer:  d,
		logger:  logger,
		port:    dnsPort,
		dotPort: dotPort,
		dots: concurrent_lru.NewConecurrentLRU[netip.Addr, *transport.Transport](dotTransportsMax, func(_ netip.Addr, t *transport.Transport) {
			t.Close()
		}),
	}
}

func matchResponse(q, r *dns.Msg) bool {
	if r.Id != q.Id || !r.Response || len(r.Question) != 1 || len(q.Question) != 1 {
		return false
	}
	a, b := q.Question[0], r.Question[0]
	return a.Qtype == b.Qtype && a.Qclass == b.Qclass && strings.EqualFold(a.Name, b.Name)
}

func (e *netExchanger) exchange(ctx context.Context, addr netip.Addr, q *dns.Msg, p proto) (*dns.Msg, error) {
	switch p {
	case protoTCP:
		return e.exchangeTCP(ctx, addr, q)
	case protoDoT:
		return e.exchangeDoT(ctx, addr, q)
	}
	return e.exchangeUDP(ctx, addr, q)
}

func bindContext(ctx context.Context, c net.Conn) func() bool {
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	return context.AfterFunc(ctx, func() {
		c.SetDeadline(time.Unix(1, 0))
	})
}

func (e *netExchanger) exchangeUDP(ctx context.Context, addr netip.Addr, q *dns.Msg) (*dns.Msg, error) {
	c, err := e.dialer.DialContext(ctx, "udp", netip.AddrPortFrom(addr, e.port).String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := bindContext(ctx, c)
	defer stop()

	if _, err := dnsutils.WriteMsgToUDP(c, q); err != nil {
		return nil, err
	}
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf[:n]); err != nil {
			continue
		}
		if !matchResponse(q, r) {
			continue
		}
		return r, nil
	}
}

func (e *netExchanger) exchangeTCP(ctx context.Context, addr netip.Addr, q *dns.Msg) (*dns.Msg, error) {
	c, err := e.dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, e.port).String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := bindContext(ctx, c)
	defer stop()

	if _, err := dnsutils.WriteMsgToTCP(c, q); err != nil {
		return nil, err
	}
	for {
		r, _, err := dnsutils.ReadMsgFromTCP(c)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if r.Id != q.Id {
			continue
		}
		if !matchResponse(q, r) {
			return nil, errMismatch
		}
		return r, nil
	}
}

func (e *netExchanger) dialTLS(ctx context.Context, addr netip.Addr) (net.Conn, error) {
	c, err := e.dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, e.dotPort).String())
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"dot"},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func (e *netExchanger) dotTransport(addr netip.Addr) (*transport.Transport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.dots.Get(addr); ok {
		return t, nil
	}
	t, err := transport.NewTransport(transport.Opts{
		Logger: e.logger,
		DialFunc: func(ctx context.Context) (net.Conn, error) {
			return e.dialTLS(ctx, addr)
		},
		WriteFunc:      dnsutils.WriteMsgToTCP,
		ReadFunc:       dnsutils.ReadMsgFromTCP,
		IdleTimeout:    dotIdleTimeout,
		EnablePipeline: true,
		MaxConns:       2,
	})
	if err != nil {
		return nil, err
	}
	e.dots.Add(addr, t)
	return t, nil
}

func (e *netExchanger) exchangeDoT(ctx context.Context, addr netip.Addr, q *dns.Msg) (*dns.Msg, error) {
	t, err := e.dotTransport(addr)
	if err != nil {
		return nil, err
	}
	r, err := t.ExchangeContext(ctx, q)
	if err != nil {
		return nil, err
	}
	if !matchResponse(q, r) {
		return nil, errMismatch
	}
	return r, nil
}

func (e *netExchanger) probeDoT(ctx context.Context, addr netip.Addr) error {
	c, err := e.dialTLS(ctx, addr)
	if err != nil {
		return err
	}
	return c.Close()
}

func (e *netExchanger) close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dots.Clean(func(netip.Addr, *transport.Transport) bool { return true })
	return nil
}
