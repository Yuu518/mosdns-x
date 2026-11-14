package recursive

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/recursor"
	"github.com/pmkol/mosdns-x/pkg/upstream"
)

const PluginType = "recursive"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*recursive)(nil)

type Args struct {
	RootHints        string `yaml:"root_hints"`
	TrustAnchor      string `yaml:"trust_anchor"`
	DisableDNSSEC    bool   `yaml:"disable_dnssec"`
	DisableQNameMin  bool   `yaml:"disable_qname_min"`
	NoIPv4           bool   `yaml:"no_ipv4"`
	NoIPv6           bool   `yaml:"no_ipv6"`
	CacheSize        int    `yaml:"cache_size"`
	LocalRoot        bool   `yaml:"local_root"`
	LocalRootSource  string `yaml:"local_root_source"`
	LocalRootFile    string `yaml:"local_root_file"`
	OpportunisticDoT bool   `yaml:"opportunistic_dot"`
	Prefetch         bool   `yaml:"prefetch"`
	PrefetchKey      bool   `yaml:"prefetch_key"`
	AutoTrustAnchor  string `yaml:"auto_trust_anchor_file"`
	Socks5           string `yaml:"socks5"`
	S5Username       string `yaml:"s5_username"`
	S5Password       string `yaml:"s5_password"`
	SoMark           int    `yaml:"so_mark"`
	BindToDevice     string `yaml:"bind_to_device"`
}

type recursive struct {
	*coremain.BP
	r *recursor.Resolver
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newRecursive(bp, args.(*Args))
}

func newOpts(bp *coremain.BP, args *Args) (recursor.Opts, error) {
	opts := recursor.Opts{
		DisableDNSSEC:    args.DisableDNSSEC,
		DisableQNameMin:  args.DisableQNameMin,
		NoIPv4:           args.NoIPv4,
		NoIPv6:           args.NoIPv6,
		CacheSize:        args.CacheSize,
		LocalRoot:        args.LocalRoot,
		LocalRootSource:  args.LocalRootSource,
		LocalRootFile:    args.LocalRootFile,
		OpportunisticDoT: args.OpportunisticDoT,
		Prefetch:         args.Prefetch,
		PrefetchKey:      args.PrefetchKey,
		AutoTrustFile:    args.AutoTrustAnchor,
		Logger:           bp.L(),
	}
	if len(args.RootHints) > 0 {
		rrs, err := recursor.ReadRRFile(args.RootHints)
		if err != nil {
			return opts, fmt.Errorf("failed to load root hints, %w", err)
		}
		opts.RootHints = rrs
	}
	if len(args.TrustAnchor) > 0 {
		rrs, err := recursor.ReadRRFile(args.TrustAnchor)
		if err != nil {
			return opts, fmt.Errorf("failed to load trust anchor, %w", err)
		}
		opts.TrustAnchors = rrs
	}
	d, err := upstream.NewDialer(&upstream.Opt{
		Socks5:       args.Socks5,
		S5Username:   args.S5Username,
		S5Password:   args.S5Password,
		SoMark:       args.SoMark,
		BindToDevice: args.BindToDevice,
	})
	if err != nil {
		return opts, fmt.Errorf("failed to init dialer, %w", err)
	}
	opts.Dialer = d
	return opts, nil
}

func newRecursive(bp *coremain.BP, args *Args) (*recursive, error) {
	opts, err := newOpts(bp, args)
	if err != nil {
		return nil, err
	}
	r, err := recursor.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to init resolver, %w", err)
	}
	p := &recursive{BP: bp, r: r}
	if bp.M() != nil {
		bp.GetMetricsReg().MustRegister(p.collectors()...)
	}
	return p, nil
}

func (p *recursive) collectors() []prometheus.Collector {
	counter := func(name, help string, f func(s recursor.Stats) uint64) prometheus.Collector {
		return prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, func() float64 {
			return float64(f(p.r.Stats()))
		})
	}
	gauge := func(name, help string, f func(s recursor.Stats) float64) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, func() float64 {
			return f(p.r.Stats())
		})
	}
	return []prometheus.Collector{
		counter("query_total", "The total number of processed queries", func(s recursor.Stats) uint64 { return s.Queries }),
		counter("err_total", "The total number of queries that failed", func(s recursor.Stats) uint64 { return s.Errors }),
		counter("upstream_query_total", "The total number of queries sent to authoritative servers", func(s recursor.Stats) uint64 { return s.UpstreamQueries }),
		counter("upstream_dot_query_total", "The total number of queries sent to authoritative servers over DoT", func(s recursor.Stats) uint64 { return s.DoTQueries }),
		counter("cache_hit_total", "The total number of lookups answered by the internal cache", func(s recursor.Stats) uint64 { return s.CacheHits }),
		counter("dnssec_secure_total", "The total number of answers validated as secure", func(s recursor.Stats) uint64 { return s.Secure }),
		counter("dnssec_insecure_total", "The total number of answers validated as insecure", func(s recursor.Stats) uint64 { return s.Insecure }),
		counter("dnssec_bogus_total", "The total number of answers validated as bogus", func(s recursor.Stats) uint64 { return s.Bogus }),
		counter("synthesized_negative_total", "The total number of negative answers synthesized from cached dnssec proofs", func(s recursor.Stats) uint64 { return s.Synthesized }),
		counter("prefetch_total", "The total number of cache entries refreshed in the background", func(s recursor.Stats) uint64 { return s.Prefetches }),
		gauge("cache_size", "Current internal cache size in entries", func(s recursor.Stats) float64 { return float64(s.CacheSize) }),
		gauge("local_root_serial", "Serial of the local root zone in use", func(s recursor.Stats) float64 { return float64(s.LocalRootSerial) }),
	}
}

func (p *recursive) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	r, err := p.r.Resolve(ctx, qCtx.Q())
	if err != nil {
		return err
	}
	qCtx.SetResponse(r)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *recursive) Close() error {
	return p.r.Close()
}
