package output

import (
	"encoding/json"
	"io"
	"sync"
)

// All message types written to stdout as JSON Lines.
// Python reads these line-by-line in real time.

type Finding struct {
	Type        string   `json:"type"`        // always "finding"
	TemplateID  string   `json:"template_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	URL         string   `json:"url"`
	MatchedAt   string   `json:"matched_at"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	CVE         string   `json:"cve,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
	OWASP       string   `json:"owasp,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Evidence    string   `json:"evidence"`
	Request     string   `json:"request,omitempty"`
	Response    string   `json:"response,omitempty"`
	CurlCommand string   `json:"curl_command,omitempty"`
	Confidence  float64  `json:"confidence"`  // 0.0–1.0 — not in Nuclei
	OOBPending  bool     `json:"oob_pending"` // true = awaiting callback confirmation
}

type Progress struct {
	Type      string `json:"type"` // always "progress"
	Done      int    `json:"done"`
	Total     int    `json:"total"`
	Findings  int    `json:"findings"`
	Current   string `json:"current_template"`
}

type Summary struct {
	Type            string  `json:"type"` // always "summary"
	TotalFindings   int     `json:"total_findings"`
	TemplatesRun    int     `json:"templates_run"`
	DurationSeconds float64 `json:"duration_seconds"`
	PagesScanned    int     `json:"pages_scanned"`
}

type ErrorMsg struct {
	Type    string `json:"type"` // always "error"
	Message string `json:"message"`
}

type Streamer struct {
	w   io.Writer
	mu  sync.Mutex
	enc *json.Encoder
}

func NewStreamer(w io.Writer) *Streamer {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Streamer{w: w, enc: enc}
}

func (s *Streamer) Finding(f Finding) {
	f.Type = "finding"
	s.write(f)
}

func (s *Streamer) Progress(done, total, findings int, current string) {
	s.write(Progress{
		Type:     "progress",
		Done:     done,
		Total:    total,
		Findings: findings,
		Current:  current,
	})
}

func (s *Streamer) Summary(totalFindings, templatesRun, pages int, dur float64) {
	s.write(Summary{
		Type:            "summary",
		TotalFindings:   totalFindings,
		TemplatesRun:    templatesRun,
		DurationSeconds: dur,
		PagesScanned:    pages,
	})
}

func (s *Streamer) Error(msg string) {
	s.write(ErrorMsg{Type: "error", Message: msg})
}

func (s *Streamer) write(v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(v)
}
