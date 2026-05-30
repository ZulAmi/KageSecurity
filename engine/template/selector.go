package template

import (
	"sort"
	"strings"
)

// Score assigns a relevance score (0.0–1.0) to each template based on how
// well its tags overlap with the detected stack fingerprint.
// Templates with a higher score run first — so a partial scan still surfaces
// the most relevant findings even if it gets killed early.
//
// This is the key difference from Nuclei, which runs templates in arbitrary
// file-system order with no awareness of the target stack.
func Score(templates []*Template, fingerprint map[string]interface{}) {
	techTags := extractTechTags(fingerprint)
	if len(techTags) == 0 {
		// No fingerprint — assign uniform baseline so order stays stable
		return
	}

	for _, t := range templates {
		t.Score = scoreTemplate(t, techTags)
	}
}

// SortByScore sorts templates descending by Score, preserving order within
// equal scores (stable sort keeps high-severity templates first when added
// by the loader in severity order).
func SortByScore(templates []*Template) {
	sort.SliceStable(templates, func(i, j int) bool {
		si, sj := templates[i].Score, templates[j].Score
		if si != sj {
			return si > sj
		}
		// Tiebreak: severity order
		return severityRank(templates[i].Severity) > severityRank(templates[j].Severity)
	})
}

func scoreTemplate(t *Template, techTags map[string]bool) float64 {
	if len(t.Tags) == 0 {
		return 0.1 // low but non-zero — still runs, just last
	}
	matches := 0
	for _, tag := range t.Tags {
		if techTags[strings.ToLower(tag)] {
			matches++
		}
	}
	if matches == 0 {
		return 0.1
	}
	// Normalise: more tag overlaps = higher score, capped at 1.0
	score := float64(matches) / float64(len(t.Tags))
	if score > 1.0 {
		score = 1.0
	}
	// Boost high-severity templates within same overlap ratio
	score += severityBoost(t.Severity)
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// extractTechTags flattens the KageSec fingerprint map into a set of lowercase
// technology keywords. The fingerprint is whatever the Python crawler detected
// (e.g. {"tech": ["nginx", "react", "next.js"], "language": "javascript"}).
func extractTechTags(fp map[string]interface{}) map[string]bool {
	tags := map[string]bool{}
	for _, v := range fp {
		switch val := v.(type) {
		case string:
			if val != "" {
				tags[strings.ToLower(val)] = true
				// Nuclei tags often use short forms: "nextjs" not "next.js"
				tags[strings.ToLower(strings.ReplaceAll(val, ".", ""))] = true
				tags[strings.ToLower(strings.ReplaceAll(val, "-", ""))] = true
			}
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok && s != "" {
					tags[strings.ToLower(s)] = true
					tags[strings.ToLower(strings.ReplaceAll(s, ".", ""))] = true
					tags[strings.ToLower(strings.ReplaceAll(s, "-", ""))] = true
				}
			}
		case []string:
			for _, s := range val {
				if s != "" {
					tags[strings.ToLower(s)] = true
				}
			}
		}
	}
	return tags
}

func severityBoost(sev string) float64 {
	switch sev {
	case "critical":
		return 0.08
	case "high":
		return 0.05
	case "medium":
		return 0.02
	}
	return 0
}

func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}
