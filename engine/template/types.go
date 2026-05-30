package template

// Template is the parsed, normalised form of a Nuclei-compatible YAML template.
type Template struct {
	ID          string
	Name        string
	Severity    string // critical|high|medium|low|info
	Description string
	Remediation string
	CVE         string
	CVSS        float64
	CWE         string
	OWASP       string
	Tags        []string
	Requests    []Request
	Source      string  // file path, for debugging
	Score       float64 // fingerprint relevance score set by selector — not in Nuclei
}

type Request struct {
	Method            string
	Paths             []string
	Headers           map[string]string
	Body              string
	MatchersCondition string // "and" | "or"
	Matchers          []Matcher
	Payloads          map[string][]string
	Attack            string // "batteringram" | "pitchfork" | "clusterbomb"
	StopAtFirstMatch  bool
}

type Matcher struct {
	Type      string   // "status" | "word" | "regex" | "header"
	Part      string   // "body" | "header" | "status"
	Words     []string
	Regex     []string
	Status    []int
	Header    string // header name for type=header
	Condition string // "and" | "or"
	Negative  bool
}

// raw YAML structs — only used during loading

type rawTemplate struct {
	ID   string  `yaml:"id"`
	Info rawInfo `yaml:"info"`
	// Nuclei uses both "requests:" and "http:"
	Requests []rawRequest `yaml:"requests"`
	HTTP     []rawRequest `yaml:"http"`
}

type rawInfo struct {
	Name           string      `yaml:"name"`
	Severity       string      `yaml:"severity"`
	Description    string      `yaml:"description"`
	Tags           interface{} `yaml:"tags"` // string or []string
	Remediation    string      `yaml:"remediation"`
	CVE            string      `yaml:"cve"`
	CVSS           float64     `yaml:"cvss"`
	CWE            string      `yaml:"cwe"`
	OWASP          string      `yaml:"owasp"`
	Classification struct {
		CVSSScore float64 `yaml:"cvss-score"`
		CVEID     string  `yaml:"cve-id"`
		CWEID     string  `yaml:"cwe-id"`
	} `yaml:"classification"`
}

type rawRequest struct {
	Method            string                 `yaml:"method"`
	Path              interface{}            `yaml:"path"`  // string or []string
	Paths             interface{}            `yaml:"paths"` // alias
	Headers           map[string]string      `yaml:"headers"`
	Body              string                 `yaml:"body"`
	MatchersCondition string                 `yaml:"matchers-condition"`
	Matchers          []rawMatcher           `yaml:"matchers"`
	Payloads          map[string]interface{} `yaml:"payloads"`
	Attack            string                 `yaml:"attack"`
	StopAtFirstMatch  bool                   `yaml:"stop-at-first-match"`
}

type rawMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Header    string   `yaml:"header"`
	Condition string   `yaml:"condition"`
	Negative  bool     `yaml:"negative"`
}
