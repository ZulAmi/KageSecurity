package template

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Result struct {
	TemplateID  string
	Title       string
	Severity    string
	URL         string
	MatchedAt   string
	Description string
	Remediation string
	CVE         string
	CWE         string
	CVSS        float64
	OWASP       string
	Tags        []string
	Evidence    string
	Request     string
	Response    string
	CurlCommand string
	Confidence  float64
	OOBPending  bool
}

// Execute runs a template against targetURL and returns any findings.
func Execute(t *Template, targetURL string, client *http.Client, extraHeaders map[string]string, oobServer string) []Result {
	variables := buildVariables(targetURL, oobServer)
	var results []Result

	for _, req := range t.Requests {
		combos := expandPayloads(req)
		for _, combo := range combos {
			merged := mergeVars(variables, combo)
			for _, pathTpl := range req.Paths {
				url := substitute(pathTpl, merged)
				status, body, headers, rawReq, rawResp, err := doRequest(req, url, merged, extraHeaders, client)
				if err != nil {
					continue
				}

				// OOB templates require a callback listener to confirm.
				// KageSec has no listener on the default OOB server, so skip
				// these to avoid unconfirmed false positives.
				if isOOBTemplate(req) {
					continue
				}

				if !Evaluate(req, status, body, headers) {
					continue
				}

				conf := Confidence(req, status, body, headers)
				snippet := body
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}

				results = append(results, Result{
					TemplateID:  t.ID,
					Title:       t.Name,
					Severity:    t.Severity,
					URL:         targetURL,
					MatchedAt:   url,
					Description: t.Description,
					Remediation: t.Remediation,
					CVE:         t.CVE,
					CWE:         t.CWE,
					CVSS:        t.CVSS,
					OWASP:       t.OWASP,
					Tags:        t.Tags,
					Evidence:    fmt.Sprintf("Template %q matched: HTTP %d | %s", t.ID, status, snippet),
					Request:     rawReq,
					Response:    rawResp[:min(len(rawResp), 500)],
					CurlCommand: buildCurl(req.Method, url, req.Headers, req.Body),
					Confidence:  conf,
				})
				if req.StopAtFirstMatch {
					return results
				}
			}
		}
	}
	return results
}

func doRequest(
	req Request, url string, vars map[string]string,
	extraHeaders map[string]string, client *http.Client,
) (int, string, map[string]string, string, string, error) {
	method := req.Method
	body := substitute(req.Body, vars)

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	httpReq, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return 0, "", nil, "", "", err
	}

	// Extra headers from KageSec (auth tokens, cookies, etc.)
	for k, v := range extraHeaders {
		httpReq.Header.Set(k, v)
	}
	// Template-specific headers (may override)
	for k, v := range req.Headers {
		httpReq.Header.Set(k, substitute(v, vars))
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, "", nil, "", "", err
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1MB
	respBody := string(rawBody)

	respHeaders := map[string]string{}
	for k, vs := range resp.Header {
		respHeaders[strings.ToLower(k)] = strings.Join(vs, ", ")
	}

	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s", method, httpReq.URL.RequestURI(), httpReq.Host)
	rawResp := fmt.Sprintf("HTTP/1.1 %d\r\n%s\r\n\r\n%s", resp.StatusCode, headersString(resp.Header), respBody[:min(len(respBody), 500)])

	return resp.StatusCode, respBody, respHeaders, rawReq, rawResp, nil
}

func buildVariables(targetURL, oobServer string) map[string]string {
	// Parse scheme + host from target URL
	scheme, host, path := splitURL(targetURL)
	port := "443"
	if scheme == "http" {
		port = "80"
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		port = host[idx+1:]
		host = host[:idx]
	}
	vars := map[string]string{
		"{{BaseURL}}":      fmt.Sprintf("%s://%s", scheme, host),
		"{{Hostname}}":     host,
		"{{Host}}":         host,
		"{{Path}}":         path,
		"{{Port}}":         port,
		"{{Scheme}}":       scheme,
		"{{RootURL}}":      fmt.Sprintf("%s://%s", scheme, host),
	}
	if oobServer != "" {
		vars["{{OOBServer}}"] = oobServer
		vars["{{interactsh-url}}"] = oobServer
		vars["{{oob-server}}"] = oobServer
	}
	return vars
}

func splitURL(u string) (scheme, host, path string) {
	scheme = "https"
	rest := u
	if strings.HasPrefix(u, "https://") {
		rest = u[8:]
	} else if strings.HasPrefix(u, "http://") {
		scheme = "http"
		rest = u[7:]
	}
	if idx := strings.Index(rest, "/"); idx >= 0 {
		host = rest[:idx]
		path = rest[idx:]
	} else {
		host = rest
		path = "/"
	}
	return
}

func substitute(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
}

func mergeVars(base, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	return merged
}

func expandPayloads(req Request) []map[string]string {
	if len(req.Payloads) == 0 {
		return []map[string]string{{}}
	}

	keys := make([]string, 0, len(req.Payloads))
	lists := make([][]string, 0, len(req.Payloads))
	for k, v := range req.Payloads {
		keys = append(keys, k)
		lists = append(lists, v)
	}

	switch req.Attack {
	case "clusterbomb":
		return cartesian(keys, lists)
	case "pitchfork":
		return pitchfork(keys, lists)
	default: // batteringram
		return batteringram(keys, lists)
	}
}

func batteringram(keys []string, lists [][]string) []map[string]string {
	maxLen := 0
	for _, l := range lists {
		if len(l) > maxLen {
			maxLen = len(l)
		}
	}
	result := make([]map[string]string, maxLen)
	for i := 0; i < maxLen; i++ {
		m := map[string]string{}
		for j, k := range keys {
			m["{{"+k+"}}"] = lists[j][i%len(lists[j])]
		}
		result[i] = m
	}
	return result
}

func pitchfork(keys []string, lists [][]string) []map[string]string {
	minLen := len(lists[0])
	for _, l := range lists {
		if len(l) < minLen {
			minLen = len(l)
		}
	}
	result := make([]map[string]string, minLen)
	for i := 0; i < minLen; i++ {
		m := map[string]string{}
		for j, k := range keys {
			m["{{"+k+"}}"] = lists[j][i]
		}
		result[i] = m
	}
	return result
}

func cartesian(keys []string, lists [][]string) []map[string]string {
	result := []map[string]string{{}}
	for idx, list := range lists {
		var next []map[string]string
		for _, existing := range result {
			for _, v := range list {
				m := make(map[string]string, len(existing)+1)
				for k, val := range existing {
					m[k] = val
				}
				m["{{"+keys[idx]+"}}"] = v
				next = append(next, m)
			}
		}
		result = next
	}
	return result
}

func isOOBTemplate(req Request) bool {
	for _, m := range req.Matchers {
		if m.Part == "interactsh_protocol" || m.Part == "interactsh_request" || m.Part == "oob" {
			return true
		}
	}
	for _, paths := range req.Paths {
		if strings.Contains(paths, "{{interactsh-url}}") || strings.Contains(paths, "{{OOBServer}}") {
			return true
		}
	}
	for _, v := range req.Headers {
		if strings.Contains(v, "{{interactsh-url}}") || strings.Contains(v, "{{OOBServer}}") {
			return true
		}
	}
	return false
}

func buildCurl(method, url string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("curl -sk -X %s", method))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf(" -H '%s: %s'", k, v))
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf(" --data '%s'", body))
	}
	sb.WriteString(fmt.Sprintf(" '%s'", url))
	return sb.String()
}

func headersString(h http.Header) string {
	var sb strings.Builder
	for k, vs := range h {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(vs, ", "))
		sb.WriteString("\r\n")
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
