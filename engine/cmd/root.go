package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ZulAmi/kagesec/engine/output"
	"github.com/ZulAmi/kagesec/engine/runner"
)

type multiFlag []string

func (m *multiFlag) String() string  { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func Execute() {
	var (
		target       = flag.String("target", "", "Target URL (required)")
		templatesDir = flag.String("templates", "", "Templates directory (required)")
		fingerprint  = flag.String("fingerprint", "{}", "JSON stack fingerprint from KageSec crawler")
		concurrency  = flag.Int("concurrency", 50, "Concurrent goroutines")
		rateLimit    = flag.Float64("rate-limit", 10.0, "Requests per second")
		timeout      = flag.Int("timeout", 10, "HTTP timeout (seconds)")
		oobURL       = flag.String("oob-url", "", "OOB callback server URL (e.g. xyz.oast.pro)")
		cookie       = flag.String("cookie", "", "Cookie header value")
		severity     = flag.String("severity", "info,low,medium,high,critical", "Severity filter (comma-separated)")
		noVerify     = flag.Bool("no-verify", false, "Skip TLS verification")
	)
	var headers multiFlag
	flag.Var(&headers, "header", "Extra request header (repeatable, format: 'Name: Value')")
	flag.Parse()

	if *target == "" || *templatesDir == "" {
		fmt.Fprintln(os.Stderr, "usage: kagesec-engine --target <url> --templates <dir>")
		os.Exit(1)
	}

	var fp map[string]interface{}
	if err := json.Unmarshal([]byte(*fingerprint), &fp); err != nil {
		fp = map[string]interface{}{}
	}

	headerMap := parseHeaders(headers)
	if *cookie != "" {
		headerMap["Cookie"] = *cookie
	}

	cfg := runner.Config{
		Target:       *target,
		TemplatesDir: *templatesDir,
		Fingerprint:  fp,
		Concurrency:  *concurrency,
		RateLimit:    *rateLimit,
		TimeoutSecs:  *timeout,
		OOBServer:    *oobURL,
		Headers:      headerMap,
		SeveritySet:  parseSeverities(*severity),
		NoVerify:     *noVerify,
		Out:          output.NewStreamer(os.Stdout),
	}

	if err := runner.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "kagesec-engine:", err)
		os.Exit(1)
	}
}

func parseSeverities(s string) map[string]bool {
	m := map[string]bool{}
	for _, sev := range strings.Split(s, ",") {
		m[strings.TrimSpace(strings.ToLower(sev))] = true
	}
	return m
}

func parseHeaders(raw []string) map[string]string {
	m := map[string]string{}
	for _, h := range raw {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}
