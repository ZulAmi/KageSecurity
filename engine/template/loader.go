package template

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var cveTagRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)

// LoadDir walks dir recursively and returns all parseable templates.
func LoadDir(dir string) ([]*Template, error) {
	var templates []*Template
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		t, parseErr := parseFile(path)
		if parseErr == nil && t != nil {
			templates = append(templates, t)
		}
		return nil
	})
	return templates, err
}

func parseFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw rawTemplate
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.ID == "" {
		return nil, fmt.Errorf("no id")
	}

	// Use http: or requests: — whichever is populated
	rawReqs := raw.Requests
	if len(rawReqs) == 0 {
		rawReqs = raw.HTTP
	}
	if len(rawReqs) == 0 {
		return nil, fmt.Errorf("no requests")
	}

	info := raw.Info
	tags := toStringSlice(info.Tags)

	// Resolve CVE from info.cve, classification, or tags
	cve := info.CVE
	if cve == "" {
		cve = info.Classification.CVEID
	}
	if cve == "" {
		for _, tag := range tags {
			if cveTagRe.MatchString(tag) {
				cve = strings.ToUpper(tag)
				break
			}
		}
	}

	// Resolve CVSS
	cvss := info.CVSS
	if cvss == 0 {
		cvss = info.Classification.CVSSScore
	}

	// Resolve CWE
	cwe := info.CWE
	if cwe == "" && info.Classification.CWEID != "" {
		cwe = info.Classification.CWEID
	}

	reqs := make([]Request, 0, len(rawReqs))
	for _, rr := range rawReqs {
		req, err := parseRequest(rr)
		if err != nil {
			continue
		}
		reqs = append(reqs, req)
	}
	if len(reqs) == 0 {
		return nil, fmt.Errorf("no valid requests")
	}

	return &Template{
		ID:          raw.ID,
		Name:        info.Name,
		Severity:    strings.ToLower(info.Severity),
		Description: info.Description,
		Remediation: info.Remediation,
		CVE:         cve,
		CVSS:        cvss,
		CWE:         cwe,
		OWASP:       info.OWASP,
		Tags:        tags,
		Requests:    reqs,
		Source:      path,
	}, nil
}

func parseRequest(rr rawRequest) (Request, error) {
	paths := toStringSlice(rr.Path)
	if len(paths) == 0 {
		paths = toStringSlice(rr.Paths)
	}
	if len(paths) == 0 {
		return Request{}, fmt.Errorf("no paths")
	}

	matchers := make([]Matcher, 0, len(rr.Matchers))
	for _, rm := range rr.Matchers {
		matchers = append(matchers, Matcher{
			Type:      strings.ToLower(orDefault(rm.Type, "word")),
			Part:      strings.ToLower(orDefault(rm.Part, "body")),
			Words:     rm.Words,
			Regex:     rm.Regex,
			Status:    rm.Status,
			Header:    strings.ToLower(rm.Header),
			Condition: strings.ToLower(orDefault(rm.Condition, "or")),
			Negative:  rm.Negative,
		})
	}

	payloads := map[string][]string{}
	for k, v := range rr.Payloads {
		switch val := v.(type) {
		case []interface{}:
			var ss []string
			for _, item := range val {
				ss = append(ss, fmt.Sprintf("%v", item))
			}
			payloads[k] = ss
		default:
			payloads[k] = []string{fmt.Sprintf("%v", v)}
		}
	}

	method := strings.ToUpper(orDefault(rr.Method, "GET"))
	mc := strings.ToLower(orDefault(rr.MatchersCondition, "or"))
	attack := strings.ToLower(orDefault(rr.Attack, "batteringram"))

	return Request{
		Method:            method,
		Paths:             paths,
		Headers:           rr.Headers,
		Body:              rr.Body,
		MatchersCondition: mc,
		Matchers:          matchers,
		Payloads:          payloads,
		Attack:            attack,
		StopAtFirstMatch:  rr.StopAtFirstMatch,
	}, nil
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s := fmt.Sprintf("%v", item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
