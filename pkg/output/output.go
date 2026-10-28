package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

var colors = map[string]string{
	"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
	"low": "\033[94m", "info": "\033[90m",
}

const reset = "\033[0m"

type Finding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Location string `json:"location,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type Report struct {
	Target    string    `json:"target"`
	Mode      string    `json:"mode"`
	StartedAt string    `json:"started_at"`
	Findings  []Finding `json:"findings"`
}

func NewReport(target, mode string) *Report {
	return &Report{Target: target, Mode: mode, StartedAt: time.Now().UTC().Format(time.RFC3339)}
}

func (r *Report) Add(title, sev, detail string, locEv ...string) {
	if _, ok := severityRank[sev]; !ok {
		sev = "info"
	}
	f := Finding{Title: title, Severity: sev, Detail: detail}
	if len(locEv) > 0 {
		f.Location = locEv[0]
	}
	if len(locEv) > 1 {
		f.Evidence = locEv[1]
	}
	r.Findings = append(r.Findings, f)
}

func (r *Report) Print() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return severityRank[r.Findings[i].Severity] > severityRank[r.Findings[j].Severity]
	})
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", s, counts[s]))
		}
	}
	color := isTTY()
	line := strings.Repeat("=", 74)
	fmt.Printf("\n%s\n Hakscan - %s - %s\n %d finding(s)   %s\n%s\n",
		line, r.Mode, r.Target, len(r.Findings), strings.Join(parts, "  "), line)
	if len(r.Findings) == 0 {
		fmt.Println(" Nothing notable found.")
		return
	}
	for _, f := range r.Findings {
		tag := strings.ToUpper(f.Severity)
		if color {
			tag = colors[f.Severity] + tag + reset
		}
		fmt.Printf("\n[%s] %s\n    %s\n", tag, f.Title, f.Detail)
		if f.Location != "" {
			fmt.Printf("    location: %s\n", f.Location)
		}
		if f.Evidence != "" {
			ev := f.Evidence
			if len(ev) > 180 {
				ev = ev[:177] + "..."
			}
			fmt.Printf("    evidence: %s\n", ev)
		}
	}
	fmt.Println()
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func WriteJSON(r *Report, path string) {
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(path, b, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot write %s: %v\n", path, err)
		return
	}
	fmt.Printf("[*] JSON report written to %s\n", path)
}

// ===========================================================================
//  HTTP client
// ===========================================================================

func Mask(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		if len(s) < 4 {
			return s
		}
		return s[:4] + "..."
	}
	return s[:6] + "..." + s[len(s)-4:]
}
