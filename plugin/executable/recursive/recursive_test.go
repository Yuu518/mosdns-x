package recursive

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

func TestArgsToOpts(t *testing.T) {
	dir := t.TempDir()
	hints := filepath.Join(dir, "hints")
	anchor := filepath.Join(dir, "anchor")
	os.WriteFile(hints, []byte(". 3600 NS a.example.\na.example. 3600 A 192.0.2.1\n"), 0o644)
	os.WriteFile(anchor, []byte(". 3600 DS 1 13 2 0000000000000000000000000000000000000000000000000000000000000000\n"), 0o644)
	args := &Args{
		RootHints:        hints,
		TrustAnchor:      anchor,
		DisableDNSSEC:    true,
		DisableQNameMin:  true,
		NoIPv6:           true,
		CacheSize:        1024,
		LocalRoot:        true,
		LocalRootSource:  "/nonexistent/root.zone",
		LocalRootFile:    "root.zone",
		OpportunisticDoT: true,
		SoMark:           1,
		BindToDevice:     "eth0",
	}
	opts, err := newOpts(coremain.NewBP("test", PluginType, nil, nil), args)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.RootHints) != 2 || len(opts.TrustAnchors) != 1 {
		t.Fatalf("files not loaded: %d hints, %d anchors", len(opts.RootHints), len(opts.TrustAnchors))
	}
	if !opts.DisableDNSSEC || !opts.DisableQNameMin || !opts.NoIPv6 || opts.NoIPv4 || opts.CacheSize != 1024 ||
		!opts.LocalRoot || opts.LocalRootSource != args.LocalRootSource || opts.LocalRootFile != "root.zone" ||
		!opts.OpportunisticDoT || opts.Dialer == nil || opts.Logger == nil {
		t.Fatalf("unexpected opts %+v", opts)
	}

	if _, err := newOpts(coremain.NewBP("test", PluginType, nil, nil), &Args{RootHints: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("missing root hints file accepted")
	}
	if _, err := newRecursive(coremain.NewBP("test", PluginType, nil, nil), &Args{NoIPv4: true, NoIPv6: true}); err == nil {
		t.Fatal("disabling both address families accepted")
	}
}

func TestExec(t *testing.T) {
	p, err := newRecursive(coremain.NewBP("test", PluginType, nil, nil), &Args{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAXFR)
	qCtx := query_context.NewContext(q, nil)
	want := new(dns.Msg)
	next := executable_seq.WrapExecutable(&executable_seq.DummyExecutable{WantR: want})
	if err := p.Exec(context.Background(), qCtx, next); err != nil {
		t.Fatal(err)
	}
	if qCtx.R() != want {
		t.Fatal("next node was not executed")
	}

	qCtx = query_context.NewContext(q, nil)
	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatal(err)
	}
	if qCtx.R() == nil || qCtx.R().Rcode != dns.RcodeNotImplemented || qCtx.R().Id != q.Id {
		t.Fatalf("unexpected response %v", qCtx.R())
	}
}
