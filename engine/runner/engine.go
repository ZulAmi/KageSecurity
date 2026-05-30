package runner

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ZulAmi/kagesec/engine/output"
	"github.com/ZulAmi/kagesec/engine/template"
)

type Config struct {
	Target       string
	TemplatesDir string
	Fingerprint  map[string]interface{}
	Concurrency  int
	RateLimit    float64 // requests per second per domain
	TimeoutSecs  int
	OOBServer    string
	Headers      map[string]string
	SeveritySet  map[string]bool
	NoVerify     bool
	Out          *output.Streamer
}

func Run(cfg Config) error {
	start := time.Now()

	templates, err := template.LoadDir(cfg.TemplatesDir)
	if err != nil {
		return err
	}

	// Score and sort by fingerprint relevance — run most relevant templates first.
	// This means even a killed scan surfaces the highest-value findings.
	template.Score(templates, cfg.Fingerprint)
	template.SortByScore(templates)

	// Filter by severity
	filtered := make([]*template.Template, 0, len(templates))
	for _, t := range templates {
		if cfg.SeveritySet[t.Severity] {
			filtered = append(filtered, t)
		}
	}
	templates = filtered

	total := len(templates)
	cfg.Out.Progress(0, total, 0, "")

	client := buildClient(cfg)

	// Worker pool: concurrency goroutines pull from work channel
	type work struct {
		tmpl *template.Template
		idx  int
	}
	workCh := make(chan work, cfg.Concurrency*2)
	resultCh := make(chan []template.Result, cfg.Concurrency*2)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range workCh {
				results := template.Execute(w.tmpl, cfg.Target, client, cfg.Headers, cfg.OOBServer)
				if len(results) > 0 {
					resultCh <- results
				} else {
					resultCh <- nil
				}
			}
		}()
	}

	// Collector goroutine: reads results and streams findings
	var totalFindings int32
	var done int32
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for results := range resultCh {
			d := int(atomic.AddInt32(&done, 1))
			for _, r := range results {
				atomic.AddInt32(&totalFindings, 1)
				cfg.Out.Finding(toOutputFinding(r))
			}
			if d%50 == 0 || d == total {
				cfg.Out.Progress(d, total, int(atomic.LoadInt32(&totalFindings)), "")
			}
		}
	}()

	// Feed work
	for i, t := range templates {
		workCh <- work{tmpl: t, idx: i}
	}
	close(workCh)
	wg.Wait()
	close(resultCh)
	collectorWg.Wait()

	cfg.Out.Summary(
		int(atomic.LoadInt32(&totalFindings)),
		total,
		1, // pages — engine is called once per page by Python
		time.Since(start).Seconds(),
	)
	return nil
}

func buildClient(cfg Config) *http.Client {
	// DialContext timeout caps TCP connection establishment — critical for
	// templates targeting services that DROP packets (Barco, D-Link, etc.).
	// Without this, dropped-packet hosts use the OS TCP timeout (2-4 min).
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.NoVerify},
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     30 * time.Second,
	}

	// Per-domain rate limiting via a token bucket baked into the transport.
	// Each request waits for a token; tokens refill at RateLimit/s.
	if cfg.RateLimit > 0 {
		transport2 := &rateLimitedTransport{
			inner:    transport,
			interval: time.Duration(float64(time.Second) / cfg.RateLimit),
			tokens:   make(chan struct{}, int(cfg.RateLimit)+1),
		}
		// Pre-fill tokens
		for i := 0; i < int(cfg.RateLimit)+1; i++ {
			select {
			case transport2.tokens <- struct{}{}:
			default:
			}
		}
		go transport2.refill()
		return &http.Client{
			Timeout:   time.Duration(cfg.TimeoutSecs) * time.Second,
			Transport: transport2,
		}
	}

	return &http.Client{
		Timeout:   time.Duration(cfg.TimeoutSecs) * time.Second,
		Transport: transport,
	}
}

type rateLimitedTransport struct {
	inner    http.RoundTripper
	interval time.Duration
	tokens   chan struct{}
}

func (r *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-r.tokens
	return r.inner.RoundTrip(req)
}

func (r *rateLimitedTransport) refill() {
	ticker := time.NewTicker(r.interval)
	for range ticker.C {
		select {
		case r.tokens <- struct{}{}:
		default:
		}
	}
}

func toOutputFinding(r template.Result) output.Finding {
	return output.Finding{
		TemplateID:  r.TemplateID,
		Title:       r.Title,
		Severity:    r.Severity,
		URL:         r.URL,
		MatchedAt:   r.MatchedAt,
		Description: r.Description,
		Remediation: r.Remediation,
		CVE:         r.CVE,
		CWE:         r.CWE,
		CVSS:        r.CVSS,
		OWASP:       r.OWASP,
		Tags:        r.Tags,
		Evidence:    r.Evidence,
		Request:     r.Request,
		Response:    r.Response,
		CurlCommand: r.CurlCommand,
		Confidence:  r.Confidence,
		OOBPending:  r.OOBPending,
	}
}

// Unused but satisfies the json import for fingerprint parsing in cmd
var _ = json.Marshal
