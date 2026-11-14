package recursor

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	D "github.com/pmkol/mosdns-x/pkg/upstream/dialer"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

func dotOn(o *Opts) {
	o.OpportunisticDoT = true
}

func TestDoTStateMachine(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).dot = true
	r := e.resolver(dotOn)
	ex := netip.MustParseAddr(addrExampleCom)
	ins := netip.MustParseAddr(addrInsecure)

	resolve(t, r, query("www.example.com.", dns.TypeA, true))
	for _, q := range e.net.queries() {
		if q.addr == ex {
			if q.proto != protoUDP {
				t.Fatal("first query to an unprobed server was not plain dns")
			}
			break
		}
	}
	waitFor(t, "probe", func() bool { return r.infra.dotStatus(ex) == dotOK })

	e.net.reset()
	resolve(t, r, query("other.example.com.", dns.TypeA, true))
	if e.net.count(func(q fakeQuery) bool { return q.addr == ex && q.proto == protoDoT }) == 0 {
		t.Fatal("dot not used after a successful probe")
	}
	if e.net.count(func(q fakeQuery) bool { return q.addr == ex && q.proto == protoUDP }) != 0 {
		t.Fatal("plain dns used after a successful probe")
	}
	if r.Stats().DoTQueries == 0 {
		t.Fatal("dot queries not counted")
	}

	resolve(t, r, query("www.insecure.com.", dns.TypeA, true))
	waitFor(t, "failed probe", func() bool { return r.infra.dotStatus(ins) == dotFailed })
	probes := e.net.probes.Load()
	resolve(t, r, query("www.insecure.com.", dns.TypeAAAA, true))
	if e.net.probes.Load() != probes {
		t.Fatal("probe repeated during the suppression period")
	}

	e.clock.Advance(25 * time.Hour)
	if r.infra.dotStatus(ins) != dotUnknown {
		t.Fatal("failure suppression did not expire")
	}
}

func TestDoTFallbackOnFailure(t *testing.T) {
	e := newTestEnv(t)
	srv := e.net.server(addrExampleCom)
	srv.dot = true
	r := e.resolver(dotOn)
	ex := netip.MustParseAddr(addrExampleCom)
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	waitFor(t, "probe", func() bool { return r.infra.dotStatus(ex) == dotOK })

	srv.dotBreak = true
	resp := resolve(t, r, query("other.example.com.", dns.TypeA, false))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	if r.infra.dotStatus(ex) != dotFailed {
		t.Fatal("dot failure not recorded")
	}
}

func TestDoTDisabledByDefault(t *testing.T) {
	e := newTestEnv(t)
	e.net.server(addrExampleCom).dot = true
	r := e.resolver()
	resolve(t, r, query("www.example.com.", dns.TypeA, false))
	time.Sleep(20 * time.Millisecond)
	if e.net.probes.Load() != 0 {
		t.Fatal("probe sent with opportunistic dot disabled")
	}
}

func TestDoTRealHandshake(t *testing.T) {
	cert, err := utils.GenerateCertificate("test")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		Net:       "tcp-tls",
		Listener:  l,
		TLSConfig: tlsConfig,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(q)
			m.Authoritative = true
			a, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.99")
			m.Answer = []dns.RR{a}
			w.WriteMsg(m)
		}),
	}
	go server.ActivateAndServe()
	defer server.Shutdown()

	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	d, err := D.NewDialer(D.DialerOpts{Dialer: &net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	ex := newNetExchanger(d, zap.NewNop())
	ex.dotPort = uint16(port)
	defer ex.close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr := netip.MustParseAddr("127.0.0.1")
	if err := ex.probeDoT(ctx, addr); err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	q := new(dns.Msg)
	q.SetQuestion("dot.test.", dns.TypeA)
	resp, err := ex.exchange(ctx, addr, q, protoDoT)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.99" {
		t.Fatalf("unexpected response %v", resp)
	}

	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, _ = net.SplitHostPort(plain.Addr().String())
	port, _ = strconv.Atoi(portStr)
	ex2 := newNetExchanger(d, zap.NewNop())
	ex2.dotPort = uint16(port)
	if err := ex2.probeDoT(ctx, addr); err == nil {
		t.Fatal("probe succeeded against a non-tls port")
	}
}
