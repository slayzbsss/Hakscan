package templates

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/slayzbsss/Hakscan/pkg/httpx"
)

const MaxNuclei = 4000

func AsStrings(v interface{}) []string {
	var out []string
	if arr, ok := v.([]interface{}); ok {
		for _, e := range arr {
			out = append(out, fmt.Sprintf("%v", e))
		}
	}
	return out
}

func AsInts(v interface{}) []int {
	var out []int
	if arr, ok := v.([]interface{}); ok {
		for _, e := range arr {
			switch n := e.(type) {
			case float64:
				out = append(out, int(n))
			case int:
				out = append(out, n)
			}
		}
	}
	return out
}

func NucleiMatch(r *httpx.Resp, matchers []interface{}, cond string) bool {
	var results []bool
	for _, mi := range matchers {
		m, _ := mi.(map[string]interface{})
		if m == nil {
			continue
		}
		t, _ := m["type"].(string)
		part, _ := m["part"].(string)
		neg, _ := m["negative"].(bool)
		ci, _ := m["case-insensitive"].(bool)
		hay := PartOf(r, part)
		if ci {
			hay = strings.ToLower(hay)
		}
		mc, _ := m["condition"].(string)
		mc = strings.ToLower(mc)
		res := false
		switch t {
		case "word":
			words := AsStrings(m["words"])
			if ci {
				for i := range words {
					words[i] = strings.ToLower(words[i])
				}
			}
			res = MatchWords(hay, words, mc == "and")
		case "status":
			res = ContainsInt(AsInts(m["status"]), r.Status)
		case "regex":
			res = MatchRegex(hay, AsStrings(m["regex"]), ci, mc == "and")
		}
		if neg {
			res = !res
		}
		results = append(results, res)
	}
	if len(results) == 0 {
		return false
	}
	return Reduce(results, cond == "and")
}

func PartOf(r *httpx.Resp, part string) string {
	switch part {
	case "header":
		return HeaderString(r)
	case "all", "raw", "response":
		return fmt.Sprintf("HTTP %d\n%s\n\n%s", r.Status, HeaderString(r), r.Body)
	}
	return r.Body
}

func HeaderString(r *httpx.Resp) string {
	var sb strings.Builder
	for k, v := range r.Headers {
		sb.WriteString(k + ": " + v + "\n")
	}
	return sb.String()
}

func MatchWords(hay string, words []string, all bool) bool {
	if len(words) == 0 {
		return false
	}
	for _, wd := range words {
		c := strings.Contains(hay, wd)
		if all && !c {
			return false
		}
		if !all && c {
			return true
		}
	}
	return all
}

func MatchRegex(hay string, pats []string, ci, all bool) bool {
	if len(pats) == 0 {
		return false
	}
	for _, p := range pats {
		if ci {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			if all {
				return false
			}
			continue
		}
		c := re.MatchString(hay)
		if all && !c {
			return false
		}
		if !all && c {
			return true
		}
	}
	return all
}

func Reduce(results []bool, and bool) bool {
	for _, r := range results {
		if and && !r {
			return false
		}
		if !and && r {
			return true
		}
	}
	return and
}

func ContainsInt(arr []int, v int) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

// ===========================================================================
//  FILE ENGINE - secret scanner
// ===========================================================================
