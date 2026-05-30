package template

import (
	"regexp"
	"strconv"
	"strings"
)

// Evaluate returns true if the response satisfies the request's matchers.
func Evaluate(req Request, status int, body string, headers map[string]string) bool {
	if len(req.Matchers) == 0 {
		return false
	}
	results := make([]bool, len(req.Matchers))
	for i, m := range req.Matchers {
		results[i] = evalMatcher(m, status, body, headers)
	}
	if req.MatchersCondition == "and" {
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	}
	// "or" — any match is enough
	for _, r := range results {
		if r {
			return true
		}
	}
	return false
}

// Confidence scores how specific a match is (0.0–1.0).
// This is the key differentiator from Nuclei's binary match/no-match.
func Confidence(req Request, status int, body string, headers map[string]string) float64 {
	if len(req.Matchers) == 0 {
		return 0
	}
	hitCount := 0
	for _, m := range req.Matchers {
		if evalMatcher(m, status, body, headers) {
			hitCount++
		}
	}
	if hitCount == 0 {
		return 0
	}

	base := matcherSpecificity(req.Matchers)

	// Bonus: AND condition with multiple matchers all hitting
	var bonus float64
	if req.MatchersCondition == "and" && hitCount == len(req.Matchers) && len(req.Matchers) >= 2 {
		bonus = 0.10
	}
	// Bonus: regex beats word in body
	if hasRegexInBody(req.Matchers) {
		bonus += 0.05
	}
	// Bonus: status + content match (corroborating signals)
	if hasStatusMatcher(req.Matchers) && hitCount >= 2 {
		bonus += 0.05
	}

	score := base + bonus
	if score > 0.99 {
		score = 0.99
	}
	return score
}

func matcherSpecificity(matchers []Matcher) float64 {
	maxSpec := 0.0
	for _, m := range matchers {
		var s float64
		switch m.Type {
		case "status":
			s = 0.35
		case "word":
			if m.Part == "body" {
				s = 0.60
			} else {
				s = 0.65
			}
		case "regex":
			if m.Part == "body" {
				s = 0.72
			} else {
				s = 0.75
			}
		case "header":
			s = 0.68
		default:
			s = 0.50
		}
		if s > maxSpec {
			maxSpec = s
		}
	}
	return maxSpec
}

func hasRegexInBody(matchers []Matcher) bool {
	for _, m := range matchers {
		if m.Type == "regex" && m.Part == "body" {
			return true
		}
	}
	return false
}

func hasStatusMatcher(matchers []Matcher) bool {
	for _, m := range matchers {
		if m.Type == "status" {
			return true
		}
	}
	return false
}

func evalMatcher(m Matcher, status int, body string, headers map[string]string) bool {
	result := evalMatcherInner(m, status, body, headers)
	if m.Negative {
		return !result
	}
	return result
}

func evalMatcherInner(m Matcher, status int, body string, headers map[string]string) bool {
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if s == status {
				return true
			}
		}
		return false

	case "word":
		target := getPart(m.Part, m.Header, status, body, headers)
		targetLower := strings.ToLower(target)
		if m.Condition == "and" {
			for _, w := range m.Words {
				if !strings.Contains(targetLower, strings.ToLower(w)) {
					return false
				}
			}
			return len(m.Words) > 0
		}
		for _, w := range m.Words {
			if strings.Contains(targetLower, strings.ToLower(w)) {
				return true
			}
		}
		return false

	case "regex":
		target := getPart(m.Part, m.Header, status, body, headers)
		if m.Condition == "and" {
			for _, pattern := range m.Regex {
				re, err := regexp.Compile("(?i)" + pattern)
				if err != nil || !re.MatchString(target) {
					return false
				}
			}
			return len(m.Regex) > 0
		}
		for _, pattern := range m.Regex {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				continue
			}
			if re.MatchString(target) {
				return true
			}
		}
		return false

	case "header":
		name := strings.ToLower(m.Header)
		target := ""
		for k, v := range headers {
			if strings.ToLower(k) == name {
				target = v
				break
			}
		}
		targetLower := strings.ToLower(target)
		for _, w := range m.Words {
			if strings.Contains(targetLower, strings.ToLower(w)) {
				return true
			}
		}
		return false
	}
	return false
}

func getPart(part, headerName string, status int, body string, headers map[string]string) string {
	switch part {
	case "body":
		return body
	case "status":
		return strconv.Itoa(status)
	case "response", "all":
		// Full HTTP response: headers + body
		var sb strings.Builder
		for k, v := range headers {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
		sb.WriteString(body)
		return sb.String()
	case "header":
		if headerName != "" {
			for k, v := range headers {
				if strings.ToLower(k) == headerName {
					return v
				}
			}
			return ""
		}
		var sb strings.Builder
		for k, v := range headers {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
		return sb.String()
	case "interactsh_protocol", "interactsh_request", "interactsh_host":
		// OOB callbacks are not implemented — never match
		return ""
	}
	// Unknown part — return empty to avoid false positives on body content
	return ""
}
