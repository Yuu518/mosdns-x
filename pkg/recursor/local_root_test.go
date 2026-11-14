package recursor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnssec/dnssectest"
)

func (e *testEnv) rootZoneText(serial uint32) string {
	z := e.zones["."]
	z.SOA().Serial = serial
	z.AddZONEMD()
	return z.Text()
}

type rootServer struct {
	mu       sync.Mutex
	body     string
	status   int
	modified time.Time
	ok       atomic.Int64
	hits     atomic.Int64
	srv      *httptest.Server
}

func newRootServer(t *testing.T, body string) *rootServer {
	rs := &rootServer{body: body, status: http.StatusOK, modified: time.Now().Add(-time.Hour)}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rs.hits.Add(1)
		rs.mu.Lock()
		body, status, mod := rs.body, rs.status, rs.modified
		rs.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if ims, err := http.ParseTime(req.Header.Get("If-Modified-Since")); err == nil && !mod.Truncate(time.Second).After(ims) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		rs.ok.Add(1)
		w.Header().Set("Last-Modified", mod.UTC().Format(http.TimeFormat))
		w.Write([]byte(body))
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *rootServer) set(body string, status int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if body != "" && body != rs.body {
		rs.body = body
		rs.modified = rs.modified.Add(time.Minute)
	}
	rs.status = status
}

func (e *testEnv) localRootResolver(rs *rootServer, mod ...func(o *Opts)) *Resolver {
	return e.resolver(append([]func(o *Opts){func(o *Opts) {
		o.LocalRoot = true
		o.LocalRootSource = rs.srv.URL + "/root.zone"
		o.localRootHTTPClient = rs.srv.Client()
		o.localRootInterval = time.Hour
	}}, mod...)...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLocalRootAnswersLocally(t *testing.T) {
	e := newTestEnv(t)
	rs := newRootServer(t, e.rootZoneText(2024010101))
	r := e.localRootResolver(rs)
	waitFor(t, "local root", r.local.active)
	if r.Stats().LocalRootSerial != 2024010101 {
		t.Fatalf("serial %d", r.Stats().LocalRootSerial)
	}

	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeA)) != 1 || !resp.AuthenticatedData {
		t.Fatalf("unexpected response %v", resp)
	}
	resp = resolve(t, r, query("www.nonexistenttld.", dns.TypeA, true))
	if resp.Rcode != dns.RcodeNameError || !resp.AuthenticatedData {
		t.Fatalf("expected a secure nxdomain from the local root, got %v", resp)
	}
	resp = resolve(t, r, query(".", dns.TypeNS, true))
	if len(answerOf(resp, dns.TypeNS)) == 0 || !resp.AuthenticatedData {
		t.Fatalf("unexpected root ns answer %v", resp)
	}
	resp = resolve(t, r, query("com.", dns.TypeDS, true))
	if len(answerOf(resp, dns.TypeDS)) == 0 || !resp.AuthenticatedData {
		t.Fatalf("unexpected ds answer %v", resp)
	}
	if n := e.net.countTo(addrRoot); n != 0 {
		t.Fatalf("root server received %d queries", n)
	}
}

func TestLocalRootRejectsBadData(t *testing.T) {
	e := newTestEnv(t)
	good := e.rootZoneText(2024010101)

	tampered := strings.Replace(good, addrCom, "10.0.1.9", 1)
	if tampered == good {
		t.Fatal("tampering failed")
	}
	rs := newRootServer(t, tampered)
	r := e.localRootResolver(rs)
	r.local.refresh()
	if r.local.active() {
		t.Fatal("zone with a bad digest was accepted")
	}

	other := dnssectest.NewKey(".")
	rs2 := newRootServer(t, good)
	r2 := e.resolver(func(o *Opts) {
		o.TrustAnchors = []dns.RR{other.DS()}
		o.LocalRoot = true
		o.LocalRootSource = rs2.srv.URL
		o.localRootHTTPClient = rs2.srv.Client()
		o.localRootInterval = time.Hour
	})
	r2.local.refresh()
	if r2.local.active() {
		t.Fatal("zone not matching the trust anchor was accepted")
	}

	noMD := strings.Builder{}
	for _, line := range strings.Split(good, "\n") {
		if !strings.Contains(line, "ZONEMD") {
			noMD.WriteString(line + "\n")
		}
	}
	rs3 := newRootServer(t, noMD.String())
	r3 := e.localRootResolver(rs3)
	r3.local.refresh()
	if r3.local.active() {
		t.Fatal("zone without zonemd was accepted")
	}
}

func TestLocalRootSerialRegression(t *testing.T) {
	e := newTestEnv(t)
	older := e.rootZoneText(2024010101)
	newer := e.rootZoneText(2024010102)
	rs := newRootServer(t, newer)
	r := e.localRootResolver(rs)
	waitFor(t, "local root", r.local.active)
	rs.set(older, http.StatusOK)
	r.local.refresh()
	if s := r.local.serial(); s != 2024010102 {
		t.Fatalf("serial went back to %d", s)
	}
}

func TestLocalRootExpiryFallsBack(t *testing.T) {
	e := newTestEnv(t)
	rs := newRootServer(t, e.rootZoneText(2024010101))
	r := e.localRootResolver(rs)
	waitFor(t, "local root", r.local.active)
	rs.set("", http.StatusInternalServerError)
	e.clock.Advance(8 * 24 * time.Hour)
	if r.local.active() {
		t.Fatal("expired local root still active")
	}
	resp := resolve(t, r, query("www.example.com.", dns.TypeA, true))
	if len(answerOf(resp, dns.TypeA)) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	if e.net.countTo(addrRoot) == 0 {
		t.Fatal("root servers were not used after expiry")
	}
}

func TestLocalRootAutoRefresh(t *testing.T) {
	e := newTestEnv(t)
	v1 := e.rootZoneText(2024010101)
	v2 := e.rootZoneText(2024010102)
	rs := newRootServer(t, v1)
	r := e.localRootResolver(rs, func(o *Opts) { o.localRootInterval = 20 * time.Millisecond })
	waitFor(t, "first load", func() bool { return r.local.serial() == 2024010101 })

	waitFor(t, "conditional requests", func() bool { return rs.hits.Load() >= 3 })
	if rs.ok.Load() != 1 {
		t.Fatalf("unchanged zone was downloaded %d times", rs.ok.Load())
	}

	rs.set(v2, http.StatusOK)
	waitFor(t, "refresh", func() bool { return r.local.serial() == 2024010102 })

	rs.set("", http.StatusInternalServerError)
	hits := rs.hits.Load()
	waitFor(t, "failed refreshes", func() bool { return rs.hits.Load() >= hits+3 })
	if !r.local.active() || r.local.serial() != 2024010102 {
		t.Fatal("old data lost after failed refreshes")
	}
}

func TestLocalRootPersistence(t *testing.T) {
	e := newTestEnv(t)
	body := e.rootZoneText(2024010101)
	file := filepath.Join(t.TempDir(), "root.zone")
	rs := newRootServer(t, body)
	r := e.localRootResolver(rs, func(o *Opts) { o.LocalRootFile = file })
	waitFor(t, "download", r.local.active)
	r.Close()

	raw, err := os.ReadFile(file)
	if err != nil || string(raw) != body {
		t.Fatalf("persisted file differs: %v", err)
	}

	down := newRootServer(t, body)
	down.set("", http.StatusInternalServerError)
	r2 := e.localRootResolver(down, func(o *Opts) { o.LocalRootFile = file })
	waitFor(t, "load from file", r2.local.active)
	e.net.reset()
	resp := resolve(t, r2, query("www.example.com.", dns.TypeA, true))
	if !resp.AuthenticatedData || e.net.countTo(addrRoot) != 0 {
		t.Fatalf("persisted zone not used: %v", resp)
	}
	r2.Close()

	if err := os.WriteFile(file, []byte(strings.Replace(body, addrCom, "10.0.1.9", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	rs3 := newRootServer(t, body)
	r3 := e.localRootResolver(rs3, func(o *Opts) { o.LocalRootFile = file })
	waitFor(t, "download after bad file", r3.local.active)
	if rs3.ok.Load() == 0 {
		t.Fatal("tampered file was used instead of downloading")
	}
	r3.Close()
	if raw, err := os.ReadFile(file); err != nil || string(raw) != body {
		t.Fatalf("tampered file not replaced: %v", err)
	}

	bad := filepath.Join(t.TempDir(), "missing", "root.zone")
	rs4 := newRootServer(t, body)
	r4 := e.localRootResolver(rs4, func(o *Opts) { o.LocalRootFile = bad })
	waitFor(t, "load with unwritable file", r4.local.active)
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("file unexpectedly written")
	}
}

func TestLocalRootFromPath(t *testing.T) {
	e := newTestEnv(t)
	file := filepath.Join(t.TempDir(), "root.zone")
	if err := os.WriteFile(file, []byte(e.rootZoneText(2024010101)), 0o644); err != nil {
		t.Fatal(err)
	}
	r := e.resolver(func(o *Opts) {
		o.LocalRoot = true
		o.LocalRootSource = file
		o.localRootInterval = time.Hour
	})
	waitFor(t, "local root from path", r.local.active)
	if err := os.WriteFile(file, []byte(e.rootZoneText(2024010102)), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	os.Chtimes(file, future, future)
	r.local.refresh()
	if r.local.serial() != 2024010102 {
		t.Fatalf("changed file not reloaded, serial %d", r.local.serial())
	}
}
