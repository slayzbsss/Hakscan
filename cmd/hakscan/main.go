// Hakscan - native web vulnerability scanner and file analyzer (Go).
//
// A single self-contained binary (like nuclei): no runtime dependencies.
//
//	WEB    hakscan https://target.com
//	       hakscan -u "https://target.com/page?id=1" --json report.json
//	FILES  hakscan app.apk   |   hakscan ./dir/
//	       APK/ZIP/JAR/binaries: AndroidManifest parser, secret scanner.
//	TEMPL  hakscan update-templates           (official nuclei templates, MIT)
//	       hakscan -t auto https://target.com
//	       hakscan -t mydir/ https://target.com   (JSON + YAML templates)
//
// Authorized targets only. Scanning without permission is illegal.
package main

import (
	"archive/zip"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	version    = "4.2"
	userAgent  = "Hakscan/4.2 (+authorized-security-testing)"
	httpTimeout = 12 * time.Second
	maxBody    = 500_000
	maxMember  = 25 * 1024 * 1024
)

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
var colors = map[string]string{
	"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
	"low": "\033[94m", "info": "\033[90m",
}

const reset = "\033[0m"

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}
func hakscanHome() string          { return filepath.Join(homeDir(), ".hakscan") }
func nucleiTemplatesDir() string   { return filepath.Join(hakscanHome(), "nuclei-templates") }

const nucleiTemplatesZip = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"

// ===========================================================================
//  Result model
// ===========================================================================

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

func newReport(target, mode string) *Report {
	return &Report{Target: target, Mode: mode, StartedAt: time.Now().UTC().Format(time.RFC3339)}
}

func (r *Report) add(title, sev, detail string, locEv ...string) {
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

func (r *Report) print() {
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

func writeJSON(r *Report, path string) {
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

type Resp struct {
	Status  int
	Headers map[string]string // lowercased; multi-values joined with "\n"
	Body    string
	URL     string
}

var followClient = &http.Client{Timeout: httpTimeout}
var noRedirectClient = &http.Client{
	Timeout: httpTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func doHTTP(rawurl, method string, extra map[string]string, follow bool) *Resp {
	req, err := http.NewRequest(method, rawurl, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range extra {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	client := followClient
	if !follow {
		client = noRedirectClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	headers := map[string]string{}
	for k, vals := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(vals, "\n")
	}
	return &Resp{Status: resp.StatusCode, Headers: headers, Body: string(body), URL: resp.Request.URL.String()}
}

// ===========================================================================
//  WEB ENGINE
// ===========================================================================

var secHeaders = []struct{ h, sev, msg string }{
	{"strict-transport-security", "medium", "HSTS missing: vulnerable to HTTP downgrade / MITM."},
	{"content-security-policy", "medium", "CSP missing: wider XSS/injection attack surface."},
	{"x-content-type-options", "low", "Missing: MIME-sniffing risk."},
	{"x-frame-options", "low", "Missing: clickjacking risk (or use CSP frame-ancestors)."},
	{"referrer-policy", "info", "Missing: URLs may leak via the Referer header."},
	{"permissions-policy", "info", "Missing: browser features are not restricted."},
	{"cross-origin-opener-policy", "info", "Missing: no cross-origin isolation."},
	{"cross-origin-resource-policy", "info", "Missing: resources embeddable cross-origin."},
}

var infoHeaders = []string{"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
	"x-generator", "x-drupal-cache", "via", "x-runtime", "x-backend-server"}

var sensitivePaths = []string{
	"/.git/HEAD", "/.git/config", "/.git/index", "/.svn/entries", "/.hg/requires",
	"/.env", "/.env.local", "/.env.production", "/.env.backup",
	"/.aws/credentials", "/.npmrc", "/.dockercfg", "/id_rsa", "/.ssh/id_rsa", "/.netrc",
	"/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
	"/www.zip", "/site.zip", "/web.zip", "/wp-config.php.bak", "/config.php.bak",
	"/.htaccess", "/.htpasswd", "/web.config",
	"/phpinfo.php", "/info.php", "/server-status", "/server-info", "/.DS_Store",
	"/package.json", "/composer.json", "/composer.lock", "/Gemfile", "/requirements.txt",
	"/Dockerfile", "/docker-compose.yml", "/.dockerenv", "/crossdomain.xml", "/clientaccesspolicy.xml",
	"/.well-known/security.txt", "/sitemap.xml", "/robots.txt",
	"/admin/", "/administrator/", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/adminer.php",
	"/.vscode/", "/.idea/workspace.xml", "/swagger.json", "/openapi.json", "/graphql",
	"/actuator", "/actuator/env", "/metrics", "/.git/", "/backup/", "/uploads/",
}

var infoPaths = map[string]bool{
	"/robots.txt": true, "/sitemap.xml": true, "/.well-known/security.txt": true,
	"/crossdomain.xml": true, "/clientaccesspolicy.xml": true, "/composer.json": true,
	"/package.json": true, "/requirements.txt": true, "/Gemfile": true,
}

var redirectParams = map[string]bool{
	"url": true, "next": true, "redirect": true, "redirect_url": true, "redirect_uri": true,
	"return": true, "returnurl": true, "return_url": true, "dest": true, "destination": true,
	"continue": true, "r": true, "u": true, "goto": true, "target": true, "link": true,
	"out": true, "to": true,
}

var sqlErrors = []string{
	"you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
	"quoted string not properly terminated", "pg_query()", "sqlite3::", "sqlstate[",
	"ora-01756", "ora-00933", "mysql_fetch", "mysqli_fetch", "psql: error",
	"syntax error at or near", "odbc microsoft access driver",
	"microsoft ole db provider for sql server", "supplied argument is not a valid mysql",
}

var stacktraceSigns = []struct{ label, sig string }{
	{"Python traceback", "traceback (most recent call last)"},
	{"Django debug page", "you're seeing this error because you have debug = true"},
	{"PHP error", "fatal error:"},
	{"Java stack trace", "at java."},
	{"Spring error", "org.springframework."},
	{"ASP.NET error", "server error in '/' application"},
	{"Rails error", "actioncontroller::"},
}

var ssti = []struct{ payload, expect string }{
	{"{{7*7}}", "49"}, {"${7*7}", "49"}, {"<%=7*7%>", "49"}, {"#{7*7}", "49"},
}

const (
	xssMark   = "hkxss9173<svg/onload=1>"
	redirProbe = "https://example.org/hk-redir-probe"
	evilHost  = "hakscan-evil.example"
)

type WebScanner struct {
	target    string
	delay     time.Duration
	templates string
	active    bool
	report    *Report
	tech      map[string]bool
}

func newWebScanner(target string, delay time.Duration, templates string, active bool) *WebScanner {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	return &WebScanner{target: target, delay: delay, templates: templates, active: active,
		report: newReport(target, "web"), tech: map[string]bool{}}
}

func (w *WebScanner) sleep() {
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
}

func (w *WebScanner) run() *Report {
	fmt.Fprintln(os.Stderr, "[!] Authorized targets only. Scanning without permission is illegal.")
	fmt.Printf("[*] Initial request -> %s\n", w.target)
	base := doHTTP(w.target, "GET", nil, true)
	if base == nil {
		w.report.add("Target unreachable", "info", "No valid HTTP response.")
		return w.report
	}
	fmt.Printf("[*] HTTP %d (%s)\n", base.Status, base.URL)
	w.checkHeaders(base)
	w.checkCookies(base)
	w.checkTLS(base.URL)
	w.checkCORS(base.URL)
	w.checkMethods(base.URL)
	w.fingerprint(base)
	w.checkStacktrace(base)
	w.checkMixedContent(base)
	w.checkInsecureForms(base)
	w.checkHostHeader(base.URL)
	w.checkSensitivePaths(base.URL)
	w.checkVCS(base.URL)
	w.checkCMS(base.URL)
	if w.active {
		w.checkParams(w.target)
	}
	if w.templates != "" {
		w.runTemplates(base.URL)
	}
	return w.report
}

func (w *WebScanner) checkHeaders(r *Resp) {
	for _, sh := range secHeaders {
		if _, ok := r.Headers[sh.h]; ok {
			continue
		}
		if sh.h == "x-frame-options" && strings.Contains(r.Headers["content-security-policy"], "frame-ancestors") {
			continue
		}
		w.report.add("Missing security header: "+sh.h, sh.sev, sh.msg)
	}
	for _, h := range infoHeaders {
		if v := strings.TrimSpace(r.Headers[h]); v != "" {
			w.report.add("Information disclosure: "+h, "info", "Reveals server technology/version.", "", h+": "+v)
		}
	}
}

func (w *WebScanner) checkCookies(r *Resp) {
	raw := r.Headers["set-cookie"]
	if raw == "" {
		return
	}
	low := strings.ToLower(raw)
	var miss []string
	for _, a := range []string{"secure", "httponly", "samesite"} {
		if !strings.Contains(low, a) {
			miss = append(miss, a)
		}
	}
	if len(miss) > 0 {
		ev := raw
		if len(ev) > 180 {
			ev = ev[:180]
		}
		w.report.add("Insecure cookie", "low", "Missing attributes: "+strings.Join(miss, ", ")+" - session theft / CSRF risk.", "", ev)
	}
}

func (w *WebScanner) checkTLS(rawurl string) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return
	}
	if u.Scheme != "https" {
		w.report.add("Unencrypted HTTP service", "medium", "Traffic travels in clear text (interception possible).")
		return
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: httpTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{ServerName: host})
	if err != nil {
		if strings.Contains(err.Error(), "certificate") {
			w.report.add("TLS certificate validation failed", "high", "Invalid/self-signed/hostname-mismatched certificate: "+err.Error())
		} else {
			w.report.add("TLS handshake error", "medium", err.Error())
		}
		return
	}
	defer conn.Close()
	st := conn.ConnectionState()
	switch st.Version {
	case tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11:
		w.report.add("Obsolete TLS protocol", "medium", "Server negotiates an old TLS/SSL version.", "", tlsName(st.Version))
	}
	if len(st.PeerCertificates) > 0 {
		exp := st.PeerCertificates[0].NotAfter
		days := int(time.Until(exp).Hours() / 24)
		if days < 0 {
			w.report.add("Expired TLS certificate", "high", fmt.Sprintf("Expired %d days ago.", -days), "", exp.String())
		} else if days < 15 {
			w.report.add("TLS certificate near expiry", "low", fmt.Sprintf("Expires in %d days.", days), "", exp.String())
		}
	}
}

func tlsName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return "unknown"
}

func (w *WebScanner) checkCORS(rawurl string) {
	for _, origin := range []string{"https://" + evilHost, "null"} {
		r := doHTTP(rawurl, "GET", map[string]string{"Origin": origin}, true)
		w.sleep()
		if r == nil {
			continue
		}
		acao := r.Headers["access-control-allow-origin"]
		acac := strings.ToLower(r.Headers["access-control-allow-credentials"])
		if acao == origin && origin == "null" {
			w.report.add("CORS allows null origin", "medium", "ACAO reflects 'null' - exploitable via sandboxed iframe.", "", "ACAO="+acao+" ACAC="+acac)
		} else if acao == origin {
			sev := "medium"
			if acac == "true" {
				sev = "high"
			}
			w.report.add("CORS reflects arbitrary origin", sev, "Server echoes attacker Origin in ACAO.", "", "ACAO="+acao+" ACAC="+acac)
		} else if acao == "*" && acac == "true" {
			w.report.add("CORS wildcard with credentials", "medium", "ACAO=* together with Allow-Credentials=true (invalid/risky).")
		}
	}
}

func (w *WebScanner) checkMethods(rawurl string) {
	r := doHTTP(rawurl, "OPTIONS", nil, true)
	w.sleep()
	if r == nil || r.Headers["allow"] == "" {
		return
	}
	allowed := strings.ToUpper(r.Headers["allow"])
	for _, m := range []string{"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"} {
		if strings.Contains(allowed, m) {
			sev := "low"
			if m == "PUT" || m == "DELETE" {
				sev = "medium"
			}
			w.report.add("Risky HTTP method allowed: "+m, sev, "May allow content modification or Cross-Site Tracing.", "", "Allow: "+r.Headers["allow"])
		}
	}
}

func (w *WebScanner) fingerprint(r *Resp) {
	b := strings.ToLower(r.Body)
	sc := strings.ToLower(r.Headers["set-cookie"])
	xp := strings.ToLower(r.Headers["x-powered-by"])
	checks := map[string]bool{
		"WordPress":    strings.Contains(b, "wp-content") || strings.Contains(b, "wp-includes"),
		"Drupal":       strings.Contains(b, "drupal") || r.Headers["x-drupal-cache"] != "",
		"Joomla":       strings.Contains(b, "joomla"),
		"Django":       strings.Contains(sc, "csrftoken"),
		"PHP":          strings.Contains(xp, "php") || strings.Contains(sc, "phpsessid"),
		"ASP.NET":      strings.Contains(xp, "asp.net") || strings.Contains(sc, "asp.net_sessionid"),
		"Java/JSP":     strings.Contains(sc, "jsessionid"),
		"Laravel":      strings.Contains(sc, "laravel_session"),
		"Express/Node": strings.Contains(xp, "express"),
	}
	for name, hit := range checks {
		if hit {
			w.tech[name] = true
		}
	}
	if len(w.tech) > 0 {
		var names []string
		for n := range w.tech {
			names = append(names, n)
		}
		sort.Strings(names)
		w.report.add("Technology fingerprint", "info", "Detected stack - useful for targeted testing.", "", strings.Join(names, ", "))
	}
}

func (w *WebScanner) checkStacktrace(r *Resp) {
	low := strings.ToLower(r.Body)
	for _, s := range stacktraceSigns {
		if strings.Contains(low, s.sig) {
			w.report.add("Verbose error / debug output ("+s.label+")", "medium", "Stack traces or debug pages can leak paths, versions and logic.", "", s.sig)
			return
		}
	}
}

var mixedRe = regexp.MustCompile(`(?i)(?:src|href|action)=["']?(http://[^"'>\s]+)`)

func (w *WebScanner) checkMixedContent(r *Resp) {
	if !strings.HasPrefix(r.URL, "https://") {
		return
	}
	m := mixedRe.FindAllStringSubmatch(r.Body, -1)
	if len(m) > 0 {
		w.report.add("Mixed content", "low", fmt.Sprintf("%d resource(s) loaded over plain HTTP on an HTTPS page.", len(m)), "", m[0][1])
	}
}

var formRe = regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)
var pwRe = regexp.MustCompile(`(?i)type=["']?password`)
var actionRe = regexp.MustCompile(`(?i)action=["']?([^"'>\s]+)`)
var csrfRe = regexp.MustCompile(`(?i)csrf|token|authenticity`)

func (w *WebScanner) checkInsecureForms(r *Resp) {
	for _, form := range formRe.FindAllString(r.Body, -1) {
		if !pwRe.MatchString(form) {
			continue
		}
		act := ""
		if m := actionRe.FindStringSubmatch(form); m != nil {
			act = m[1]
		}
		if strings.HasPrefix(act, "http://") {
			w.report.add("Password form submits over HTTP", "high", "Credentials sent in clear text.", "", act)
		} else if !csrfRe.MatchString(form) {
			w.report.add("Form without apparent CSRF token", "low", "A sensitive form has no visible CSRF token field.")
			break
		}
	}
}

func (w *WebScanner) checkHostHeader(rawurl string) {
	r := doHTTP(rawurl, "GET", map[string]string{"Host": evilHost}, false)
	w.sleep()
	if r == nil {
		return
	}
	if strings.Contains(r.Headers["location"], evilHost) {
		w.report.add("Host header injection (redirect)", "medium", "Spoofed Host header is reflected in the redirect Location.", "", "Location: "+r.Headers["location"])
	} else if strings.Contains(r.Body, evilHost) {
		w.report.add("Host header reflected in body", "low", "Spoofed Host appears in the response body (cache poisoning risk).")
	}
}

func (w *WebScanner) checkSensitivePaths(base string) {
	fmt.Println("[*] Probing for exposed sensitive files/paths")
	for _, p := range sensitivePaths {
		r := doHTTP(joinURL(base, p), "GET", nil, true)
		w.sleep()
		if r == nil || r.Status != 200 || strings.TrimSpace(r.Body) == "" {
			continue
		}
		snippet := truncate(strings.ReplaceAll(strings.TrimSpace(r.Body), "\n", " "), 120)
		if strings.HasSuffix(p, "/") {
			if strings.Contains(strings.ToLower(r.Body), "index of /") {
				w.report.add("Directory listing enabled: "+p, "medium", "Server exposes the folder contents.", "", snippet)
			}
			continue
		}
		sev := "high"
		if infoPaths[p] {
			sev = "info"
		}
		w.report.add("Exposed resource: "+p, sev, "Potentially sensitive file publicly accessible.", "", "HTTP 200 - "+snippet)
	}
}

var envRe = regexp.MustCompile(`(?m)^[A-Z0-9_]+\s*=`)

func (w *WebScanner) checkVCS(base string) {
	r := doHTTP(joinURL(base, "/.git/config"), "GET", nil, true)
	w.sleep()
	if r != nil && r.Status == 200 && strings.Contains(r.Body, "[core]") {
		w.report.add("Git repository exposed", "high", "/.git/config is readable - full source history may be downloadable.", "", truncate(strings.ReplaceAll(strings.TrimSpace(r.Body), "\n", " "), 120))
	}
	r = doHTTP(joinURL(base, "/.env"), "GET", nil, true)
	w.sleep()
	if r != nil && r.Status == 200 && envRe.MatchString(r.Body) {
		w.report.add(".env file exposed", "critical", "Environment file with configuration/secrets is publicly readable.", "", truncate(strings.ReplaceAll(strings.TrimSpace(r.Body), "\n", " "), 120))
	}
}

var slugRe = regexp.MustCompile(`"slug":"([^"]+)"`)

func (w *WebScanner) checkCMS(base string) {
	if !w.tech["WordPress"] {
		return
	}
	fmt.Println("[*] WordPress detected - running CMS checks")
	r := doHTTP(joinURL(base, "/wp-json/wp/v2/users"), "GET", nil, true)
	w.sleep()
	if r != nil && r.Status == 200 && strings.Contains(r.Body, `"slug"`) {
		var names []string
		for _, m := range slugRe.FindAllStringSubmatch(r.Body, 10) {
			names = append(names, m[1])
		}
		w.report.add("WordPress user enumeration (REST API)", "medium", "/wp-json/wp/v2/users exposes usernames.", "", strings.Join(names, ", "))
	}
	r = doHTTP(joinURL(base, "/xmlrpc.php"), "GET", nil, true)
	w.sleep()
	if r != nil && (r.Status == 200 || r.Status == 405) {
		w.report.add("WordPress xmlrpc.php reachable", "low", "xmlrpc.php can be abused for brute force / pingback DDoS.")
	}
}

// --- active parameter tests ---

func (w *WebScanner) variants(rawurl, payload string, only map[string]bool) [][2]string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil
	}
	q := u.Query()
	var keys []string
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out [][2]string
	for _, k := range keys {
		if only != nil && !only[strings.ToLower(k)] {
			continue
		}
		nq, _ := url.ParseQuery(u.RawQuery)
		nq.Set(k, payload)
		u2 := *u
		u2.RawQuery = nq.Encode()
		out = append(out, [2]string{k, u2.String()})
	}
	return out
}

func (w *WebScanner) checkParams(rawurl string) {
	u, _ := url.Parse(rawurl)
	if u == nil || u.RawQuery == "" {
		fmt.Println("[*] No query parameters (?x=y): active injection tests skipped")
		return
	}
	fmt.Println("[*] Active parameter tests (XSS / SQLi / SSTI / LFI / cmd / CRLF / redirect)")
	for _, v := range w.variants(rawurl, xssMark, nil) {
		r := doHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil && strings.Contains(r.Body, xssMark) {
			w.report.add("Reflected XSS", "high", "Parameter '"+v[0]+"' is reflected unescaped into the response.", v[0], v[1])
		}
	}
	for _, v := range w.variants(rawurl, "hk'\"`)", nil) {
		r := doHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil {
			low := strings.ToLower(r.Body)
			for _, sig := range sqlErrors {
				if strings.Contains(low, sig) {
					w.report.add("SQL error triggered (possible SQLi)", "high", "Parameter '"+v[0]+"' triggers a database error.", v[0], sig)
					break
				}
			}
		}
	}
	for _, s := range ssti {
		for _, v := range w.variants(rawurl, s.payload, nil) {
			r := doHTTP(v[1], "GET", nil, true)
			w.sleep()
			if r != nil && strings.Contains(r.Body, s.expect) && !strings.Contains(r.Body, s.payload) {
				w.report.add("Server-side template injection (SSTI)", "high", "Parameter '"+v[0]+"': '"+s.payload+"' evaluated to '"+s.expect+"'.", v[0], s.payload+" -> "+s.expect)
			}
		}
	}
	for _, v := range w.variants(rawurl, "../../../../../../etc/passwd", nil) {
		r := doHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil && strings.Contains(r.Body, "root:x:0:0:") {
			w.report.add("Local file inclusion / path traversal", "critical", "Parameter '"+v[0]+"' reads arbitrary local files.", v[0], "root:x:0:0: found")
		}
	}
	cmdRe := regexp.MustCompile(`uid=\d+\(.+?\) gid=\d+\(`)
	for _, v := range w.variants(rawurl, ";id", nil) {
		r := doHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil && cmdRe.MatchString(r.Body) {
			w.report.add("OS command injection", "critical", "Parameter '"+v[0]+"' executes shell commands.", v[0], "uid=... gid=... found")
		}
	}
	for _, v := range w.variants(rawurl, "hk%0d%0aHakscan-Injected:1", nil) {
		r := doHTTP(v[1], "GET", nil, false)
		w.sleep()
		if r != nil {
			if _, ok := r.Headers["hakscan-injected"]; ok {
				w.report.add("CRLF / HTTP response header injection", "high", "Parameter '"+v[0]+"' injects response headers.", v[0], "Hakscan-Injected header reflected")
			}
		}
	}
	for _, v := range w.variants(rawurl, redirProbe, redirectParams) {
		r := doHTTP(v[1], "GET", nil, false)
		w.sleep()
		if r != nil && strings.Contains(r.Headers["location"], "example.org/hk-redir-probe") {
			w.report.add("Open redirect", "medium", "Parameter '"+v[0]+"' controls an external redirect.", v[0], v[1]+" -> "+r.Headers["location"])
		}
	}
}

// ===========================================================================
//  Templates: custom JSON + official nuclei YAML
// ===========================================================================

const maxNuclei = 4000

func (w *WebScanner) runTemplates(base string) {
	root := w.templates
	if root == "auto" || root == "nuclei" {
		root = nucleiTemplatesDir()
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		w.report.add("Template directory not found", "info", root)
		if root == nucleiTemplatesDir() {
			w.report.add("Hint", "info", "Run 'hakscan update-templates' first.")
		}
		return
	}
	var jsonFiles, yamlFiles []string
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json":
			jsonFiles = append(jsonFiles, p)
		case ".yaml", ".yml":
			yamlFiles = append(yamlFiles, p)
		}
		return nil
	})
	u, _ := url.Parse(base)
	origin := base
	if u != nil {
		origin = u.Scheme + "://" + u.Host
	}
	fmt.Printf("[*] Templates: %d custom (JSON), %d nuclei (YAML)\n", len(jsonFiles), len(yamlFiles))
	for _, fp := range jsonFiles {
		var tpl map[string]interface{}
		b, err := os.ReadFile(fp)
		if err != nil || json.Unmarshal(b, &tpl) != nil {
			continue
		}
		if kind, _ := tpl["kind"].(string); kind == "secret" {
			continue
		}
		if tpl["matchers"] == nil && tpl["path"] == nil {
			continue
		}
		w.runJSONTemplate(origin, tpl, filepath.Base(fp))
	}
	if len(yamlFiles) > 0 {
		w.runNucleiTemplates(origin, yamlFiles)
	}
}

func asStrings(v interface{}) []string {
	var out []string
	if arr, ok := v.([]interface{}); ok {
		for _, e := range arr {
			out = append(out, fmt.Sprintf("%v", e))
		}
	}
	return out
}

func asInts(v interface{}) []int {
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

func (w *WebScanner) runJSONTemplate(origin string, tpl map[string]interface{}, name string) {
	path, _ := tpl["path"].(string)
	if path == "" {
		path = "/"
	}
	method, _ := tpl["method"].(string)
	if method == "" {
		method = "GET"
	}
	r := doHTTP(joinURL(origin, path), strings.ToUpper(method), nil, true)
	w.sleep()
	if r == nil {
		return
	}
	cond, _ := tpl["matchers-condition"].(string)
	cond = strings.ToLower(cond)
	matchers, _ := tpl["matchers"].([]interface{})
	var results []bool
	for _, mi := range matchers {
		m, _ := mi.(map[string]interface{})
		if m == nil {
			continue
		}
		part, _ := m["part"].(string)
		hay := r.Body
		if part == "header" {
			hay = headerString(r)
		}
		switch m["type"] {
		case "status":
			results = append(results, containsInt(asInts(m["values"]), r.Status))
		case "word":
			vals := asStrings(m["values"])
			all, _ := m["all"].(bool)
			results = append(results, matchWords(hay, vals, all))
		case "regex":
			results = append(results, matchRegex(hay, asStrings(m["values"]), false, false))
		default:
			results = append(results, false)
		}
	}
	if len(results) == 0 {
		return
	}
	ok := reduce(results, cond == "and")
	if ok {
		title, _ := tpl["name"].(string)
		if title == "" {
			title = name
		}
		sev, _ := tpl["severity"].(string)
		desc, _ := tpl["description"].(string)
		if desc == "" {
			desc = "Custom template matched."
		}
		w.report.add(title, sev, desc, path, name)
	}
}

func (w *WebScanner) runNucleiTemplates(origin string, files []string) {
	if len(files) > maxNuclei {
		fmt.Printf("[!] %d templates found; limiting to %d. Point -t at a subfolder to narrow scope.\n", len(files), maxNuclei)
		files = files[:maxNuclei]
	}
	run, matched, skipped := 0, 0, 0
	for _, fp := range files {
		b, err := os.ReadFile(fp)
		if err != nil {
			skipped++
			continue
		}
		var tpl map[string]interface{}
		if yaml.Unmarshal(b, &tpl) != nil || tpl == nil {
			skipped++
			continue
		}
		res := w.runOneNuclei(origin, tpl)
		if res < 0 {
			skipped++
		} else {
			run++
			if res == 1 {
				matched++
			}
		}
		w.sleep()
	}
	w.report.add("YAML templates executed", "info",
		fmt.Sprintf("%d run, %d matched, %d skipped (unsupported construct or parse error).", run, matched, skipped))
}

// returns 1=match, 0=ran no match, -1=unsupported
func (w *WebScanner) runOneNuclei(origin string, tpl map[string]interface{}) int {
	reqs, ok := tpl["http"].([]interface{})
	if !ok {
		reqs, ok = tpl["requests"].([]interface{})
	}
	if !ok || len(reqs) == 0 {
		return -1
	}
	block, _ := reqs[0].(map[string]interface{})
	if block == nil || block["raw"] != nil {
		return -1
	}
	paths := asStrings(block["path"])
	matchers, _ := block["matchers"].([]interface{})
	if len(paths) == 0 || len(matchers) == 0 {
		return -1
	}
	for _, mi := range matchers {
		m, _ := mi.(map[string]interface{})
		if m == nil {
			return -1
		}
		t, _ := m["type"].(string)
		if t != "word" && t != "status" && t != "regex" {
			return -1
		}
	}
	method, _ := block["method"].(string)
	if method == "" {
		method = "GET"
	}
	cond, _ := block["matchers-condition"].(string)
	cond = strings.ToLower(cond)
	host := ""
	if u, _ := url.Parse(origin); u != nil {
		host = u.Host
	}
	info, _ := tpl["info"].(map[string]interface{})
	ran := false
	if len(paths) > 5 {
		paths = paths[:5]
	}
	for _, rp := range paths {
		u := strings.ReplaceAll(rp, "{{BaseURL}}", origin)
		u = strings.ReplaceAll(u, "{{Hostname}}", host)
		if strings.Contains(u, "{{") {
			return -1
		}
		r := doHTTP(u, strings.ToUpper(method), nil, true)
		w.sleep()
		if r == nil {
			continue
		}
		ran = true
		if w.nucleiMatch(r, matchers, cond) {
			name, _ := info["name"].(string)
			if name == "" {
				name, _ = tpl["id"].(string)
			}
			sev, _ := info["severity"].(string)
			desc, _ := info["description"].(string)
			if desc == "" {
				desc = "nuclei template matched."
			}
			id, _ := tpl["id"].(string)
			w.report.add(name, sev, truncate(strings.TrimSpace(desc), 200), u, id)
			return 1
		}
	}
	if ran {
		return 0
	}
	return -1
}

func (w *WebScanner) nucleiMatch(r *Resp, matchers []interface{}, cond string) bool {
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
		hay := partOf(r, part)
		if ci {
			hay = strings.ToLower(hay)
		}
		mc, _ := m["condition"].(string)
		mc = strings.ToLower(mc)
		res := false
		switch t {
		case "word":
			words := asStrings(m["words"])
			if ci {
				for i := range words {
					words[i] = strings.ToLower(words[i])
				}
			}
			res = matchWords(hay, words, mc == "and")
		case "status":
			res = containsInt(asInts(m["status"]), r.Status)
		case "regex":
			res = matchRegex(hay, asStrings(m["regex"]), ci, mc == "and")
		}
		if neg {
			res = !res
		}
		results = append(results, res)
	}
	if len(results) == 0 {
		return false
	}
	return reduce(results, cond == "and")
}

func partOf(r *Resp, part string) string {
	switch part {
	case "header":
		return headerString(r)
	case "all", "raw", "response":
		return fmt.Sprintf("HTTP %d\n%s\n\n%s", r.Status, headerString(r), r.Body)
	}
	return r.Body
}

func headerString(r *Resp) string {
	var sb strings.Builder
	for k, v := range r.Headers {
		sb.WriteString(k + ": " + v + "\n")
	}
	return sb.String()
}

func matchWords(hay string, words []string, all bool) bool {
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

func matchRegex(hay string, pats []string, ci, all bool) bool {
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

func reduce(results []bool, and bool) bool {
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

func containsInt(arr []int, v int) bool {
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

type secretPat struct {
	name, sev string
	re        *regexp.Regexp
}

var secretPatterns = []secretPat{
	{"Private key block (PEM)", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"AWS Access Key ID", "high", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"AWS Secret Access Key", "high", regexp.MustCompile(`(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`)},
	{"Google API key", "high", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"Google OAuth client", "medium", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
	{"GCP service account", "high", regexp.MustCompile(`"type"\s*:\s*"service_account"`)},
	{"GitHub token", "high", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36}\b`)},
	{"GitLab token", "high", regexp.MustCompile(`\bglpat-[0-9A-Za-z\-_]{20}\b`)},
	{"Slack token", "high", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"Slack webhook", "medium", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`)},
	{"Discord webhook", "medium", regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`)},
	{"Telegram bot token", "medium", regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`)},
	{"Stripe live key", "critical", regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,}`)},
	{"Twilio SID", "medium", regexp.MustCompile(`\bAC[a-z0-9]{32}\b`)},
	{"SendGrid API key", "high", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)},
	{"npm token", "high", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"JWT", "low", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"Firebase DB URL", "medium", regexp.MustCompile(`[a-z0-9.-]+\.firebaseio\.com`)},
	{"Basic auth in URL", "high", regexp.MustCompile(`https?://[^/\s:@]+:[^/\s:@]+@[A-Za-z0-9.-]+`)},
	{"DB connection string", "high", regexp.MustCompile(`\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'"]+`)},
	{"Hardcoded secret (assignment)", "low", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|passwd|password|token|private[_-]?key|access[_-]?key)['"]?\s*[:=]\s*['"][^'"\s]{8,}['"]`)},
}

var extraSecretPatterns []secretPat

var urlPattern = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
var ipPattern = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b`)
var printableRun = regexp.MustCompile(`[\x20-\x7e]{6,}`)

var dangerousPerms = map[string]bool{
	"android.permission.READ_SMS": true, "android.permission.SEND_SMS": true,
	"android.permission.RECEIVE_SMS": true, "android.permission.READ_CONTACTS": true,
	"android.permission.ACCESS_FINE_LOCATION": true, "android.permission.RECORD_AUDIO": true,
	"android.permission.CAMERA": true, "android.permission.READ_EXTERNAL_STORAGE": true,
	"android.permission.WRITE_EXTERNAL_STORAGE": true, "android.permission.READ_CALL_LOG": true,
	"android.permission.READ_PHONE_STATE": true, "android.permission.SYSTEM_ALERT_WINDOW": true,
	"android.permission.REQUEST_INSTALL_PACKAGES": true,
}

func mask(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		if len(s) < 4 {
			return s
		}
		return s[:4] + "..."
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func looksBinary(data []byte) bool {
	n := len(data)
	if n > 4096 {
		n = 4096
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func extractStrings(data []byte) string {
	var parts []string
	for _, m := range printableRun.FindAll(data, -1) {
		parts = append(parts, string(m))
	}
	return strings.Join(parts, "\n")
}

func textFromBytes(data []byte) string {
	if looksBinary(data) {
		return extractStrings(data)
	}
	return string(data)
}

type seenKey struct{ name, snippet, loc string }

func scanSecrets(text, location string, rep *Report, seen map[seenKey]bool) {
	all := append(append([]secretPat{}, secretPatterns...), extraSecretPatterns...)
	for _, p := range all {
		for _, m := range p.re.FindAllString(text, -1) {
			sn := m
			if len(sn) > 40 {
				sn = sn[:40]
			}
			k := seenKey{p.name, sn, location}
			if seen[k] {
				continue
			}
			seen[k] = true
			rep.add("Potential secret: "+p.name, p.sev, "Possibly hardcoded credential/key.", location, mask(m))
		}
	}
}

func loadSecretTemplates(dir string) []secretPat {
	var out []secretPat
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return out
	}
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		var t map[string]interface{}
		if json.Unmarshal(b, &t) != nil {
			return nil
		}
		if kind, _ := t["kind"].(string); kind != "secret" {
			return nil
		}
		rx, _ := t["regex"].(string)
		if rx == "" {
			return nil
		}
		re, e := regexp.Compile(rx)
		if e != nil {
			return nil
		}
		name, _ := t["name"].(string)
		if name == "" {
			name = "custom secret"
		}
		sev, _ := t["severity"].(string)
		if sev == "" {
			sev = "low"
		}
		out = append(out, secretPat{name, sev, re})
		return nil
	})
	return out
}

// ===========================================================================
//  AndroidManifest.xml (AXML) parser
// ===========================================================================

type axmlElement struct {
	tag   string
	attrs map[string]string
}

func parseAXML(d []byte) (elems []axmlElement, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("axml parse panic")
		}
	}()
	if len(d) < 8 || binary.LittleEndian.Uint16(d[0:2]) != 0x0003 {
		return nil, fmt.Errorf("invalid AXML header")
	}
	var strs []string
	off, n := 8, len(d)
	readStr := func(p int, utf8 bool) string {
		if p < 0 || p >= len(d) {
			return ""
		}
		if utf8 {
			if d[p]&0x80 != 0 {
				p += 2
			} else {
				p++
			}
			blen := int(d[p])
			if blen&0x80 != 0 {
				blen = (blen&0x7f)<<8 | int(d[p+1])
				p += 2
			} else {
				p++
			}
			if p+blen > len(d) {
				return ""
			}
			return string(d[p : p+blen])
		}
		ln := int(binary.LittleEndian.Uint16(d[p:]))
		if ln&0x8000 != 0 {
			ln = (ln&0x7fff)<<16 | int(binary.LittleEndian.Uint16(d[p+2:]))
			p += 4
		} else {
			p += 2
		}
		if p+ln*2 > len(d) {
			return ""
		}
		u16 := make([]uint16, ln)
		for i := 0; i < ln; i++ {
			u16[i] = binary.LittleEndian.Uint16(d[p+i*2:])
		}
		return string(utf16Decode(u16))
	}
	strAt := func(idx uint32) string {
		if idx != 0xFFFFFFFF && int(idx) < len(strs) {
			return strs[idx]
		}
		return ""
	}
	for off+8 <= n {
		ctype := binary.LittleEndian.Uint16(d[off:])
		csize := int(binary.LittleEndian.Uint32(d[off+4:]))
		if csize < 8 || off+csize > n {
			break
		}
		switch ctype {
		case 0x0001: // string pool
			count := int(binary.LittleEndian.Uint32(d[off+8:]))
			flags := binary.LittleEndian.Uint32(d[off+16:])
			stringsStart := int(binary.LittleEndian.Uint32(d[off+20:]))
			utf8 := flags&0x0100 != 0
			offsetsBase := off + 28
			dataBase := off + stringsStart
			strs = make([]string, 0, count)
			for i := 0; i < count; i++ {
				if offsetsBase+i*4+4 > len(d) {
					break
				}
				so := int(binary.LittleEndian.Uint32(d[offsetsBase+i*4:]))
				strs = append(strs, readStr(dataBase+so, utf8))
			}
		case 0x0102: // start element
			if off+28 > n {
				break
			}
			nameIdx := binary.LittleEndian.Uint32(d[off+20:])
			attrStart := int(binary.LittleEndian.Uint16(d[off+24:]))
			attrCount := int(binary.LittleEndian.Uint16(d[off+28:]))
			attrs := map[string]string{}
			base := off + 16 + attrStart
			for i := 0; i < attrCount; i++ {
				a := base + i*20
				if a+20 > len(d) {
					break
				}
				aname := binary.LittleEndian.Uint32(d[a+4:])
				raw := binary.LittleEndian.Uint32(d[a+8:])
				dtype := d[a+15]
				ddata := binary.LittleEndian.Uint32(d[a+16:])
				attrs[strAt(aname)] = typedValue(raw, dtype, ddata, strs, strAt)
			}
			elems = append(elems, axmlElement{tag: strAt(nameIdx), attrs: attrs})
		}
		off += csize
	}
	return elems, nil
}

func typedValue(raw uint32, dtype byte, data uint32, strs []string, strAt func(uint32) string) string {
	if raw != 0xFFFFFFFF {
		if s := strAt(raw); s != "" {
			return s
		}
	}
	switch dtype {
	case 0x12:
		if data != 0 {
			return "true"
		}
		return "false"
	case 0x03:
		return strAt(data)
	}
	return fmt.Sprintf("%d", int32(data))
}

func utf16Decode(u []uint16) []rune {
	var out []rune
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c >= 0xD800 && c <= 0xDBFF && i+1 < len(u) {
			c2 := u[i+1]
			if c2 >= 0xDC00 && c2 <= 0xDFFF {
				out = append(out, rune((int(c-0xD800)<<10)+int(c2-0xDC00)+0x10000))
				i++
				continue
			}
		}
		out = append(out, rune(c))
	}
	return out
}

// ===========================================================================
//  FILE ENGINE - archives, directories
// ===========================================================================

var archiveExt = map[string]bool{".apk": true, ".aab": true, ".xapk": true, ".ipa": true,
	".jar": true, ".war": true, ".zip": true}

func analyzeManifest(data []byte, rep *Report) {
	elems, err := parseAXML(data)
	if err != nil {
		rep.add("AndroidManifest not parsed", "info", "AXML parsing failed; string analysis only.", "AndroidManifest.xml")
		return
	}
	var perms []string
	for _, e := range elems {
		switch e.tag {
		case "application":
			if e.attrs["debuggable"] == "true" {
				rep.add("Debuggable APK", "high", `android:debuggable="true": debugging possible in production.`, "application")
			}
			if e.attrs["allowBackup"] == "true" {
				rep.add("Backup allowed (allowBackup)", "low", `android:allowBackup="true": data extractable via adb.`, "application")
			}
			if e.attrs["usesCleartextTraffic"] == "true" {
				rep.add("Cleartext traffic allowed", "medium", `android:usesCleartextTraffic="true": plain HTTP permitted.`, "application")
			}
			if e.attrs["testOnly"] == "true" {
				rep.add("testOnly flag set", "low", `android:testOnly="true": debug/test build.`, "application")
			}
			if _, ok := e.attrs["networkSecurityConfig"]; ok {
				rep.add("Network Security Config present", "info", "Inspect it: may allow cleartext or custom CAs.", "application")
			}
		case "activity", "service", "receiver", "provider":
			if e.attrs["exported"] == "true" {
				if _, ok := e.attrs["permission"]; !ok {
					rep.add("Exported component without permission: "+e.tag, "medium", "Reachable by other apps with no protection.", e.attrs["name"])
				}
			}
		case "uses-permission":
			if n := e.attrs["name"]; n != "" {
				perms = append(perms, n)
			}
		case "meta-data":
			val := e.attrs["value"]
			nm := e.attrs["name"]
			if regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`).MatchString(val) || strings.Contains(strings.ToUpper(nm), "API_KEY") {
				ev := nm
				if val != "" {
					ev = mask(val)
				}
				rep.add("Embedded API key in manifest meta-data", "high", "meta-data '"+nm+"' may hold an API key.", "meta-data", ev)
			}
		}
	}
	var dang []string
	for _, p := range perms {
		if dangerousPerms[p] {
			dang = append(dang, p)
		}
	}
	if len(dang) > 0 {
		sort.Strings(dang)
		if len(dang) > 12 {
			dang = dang[:12]
		}
		rep.add(fmt.Sprintf("Dangerous permissions requested (%d)", len(dang)), "info", "App requests sensitive permissions.", "", strings.Join(dang, ", "))
	}
}

func analyzeArchive(path string, rep *Report) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		rep.add("Unreadable archive", "info", "Not a valid ZIP.", filepath.Base(path))
		return
	}
	defer zr.Close()
	seen := map[seenKey]bool{}
	urls := map[string]bool{}
	ips := map[string]bool{}
	hasDex := false
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 > maxMember {
			continue
		}
		if f.Name == "classes.dex" {
			hasDex = true
		}
		rc, e := f.Open()
		if e != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, maxMember))
		rc.Close()
		if filepath.Base(f.Name) == "AndroidManifest.xml" && !strings.Contains(f.Name, "/") {
			analyzeManifest(data, rep)
		}
		scanSecrets(textFromBytes(data), f.Name, rep, seen)
		for _, m := range urlPattern.FindAll(data, -1) {
			if u, e := url.Parse(string(m)); e == nil && u.Hostname() != "" {
				h := u.Hostname()
				if !strings.HasSuffix(h, ".google.com") && !strings.HasSuffix(h, ".android.com") &&
					!strings.HasSuffix(h, ".w3.org") && !strings.Contains(h, "schemas.android.com") {
					urls[h] = true
				}
			}
		}
		for _, m := range ipPattern.FindAll(data, -1) {
			ip := string(m)
			if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "0.") && !strings.HasPrefix(ip, "255.") {
				ips[ip] = true
			}
		}
	}
	if hasDex {
		rep.add("Android application (DEX present)", "info", "classes.dex found in the archive.", "classes.dex")
	}
	if len(urls) > 0 {
		rep.add(fmt.Sprintf("Referenced network endpoints (%d)", len(urls)), "info", "Domains extracted - recon / attack surface leads.", "", joinSorted(urls, 15))
	}
	if len(ips) > 0 {
		rep.add(fmt.Sprintf("Hardcoded IP addresses (%d)", len(ips)), "info", "IPs embedded in the app.", "", joinSorted(ips, 10))
	}
}

func analyzeSingleFile(path string, rep *Report) {
	data, err := os.ReadFile(path)
	if err != nil {
		rep.add("Unreadable file", "info", err.Error(), path)
		return
	}
	if len(data) > maxMember {
		data = data[:maxMember]
	}
	scanSecrets(textFromBytes(data), filepath.Base(path), rep, map[seenKey]bool{})
}

func analyzeDirectory(root string, rep *Report) {
	seen := map[seenKey]bool{}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			if strings.Contains(p, ".git") || strings.Contains(p, "node_modules") || strings.Contains(p, "__pycache__") {
				return filepath.SkipDir
			}
			return nil
		}
		if archiveExt[strings.ToLower(filepath.Ext(p))] {
			analyzeArchive(p, rep)
			return nil
		}
		if fi.Size() > maxMember {
			return nil
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		scanSecrets(textFromBytes(data), rel, rep, seen)
		return nil
	})
}

func analyzeFileTarget(target, jsonOut, templates string) int {
	fi, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Target not found: %s\n", target)
		return 2
	}
	extraSecretPatterns = nil
	if templates != "" {
		tdir := templates
		if templates == "auto" || templates == "nuclei" {
			tdir = nucleiTemplatesDir()
		}
		extraSecretPatterns = loadSecretTemplates(tdir)
		if len(extraSecretPatterns) > 0 {
			fmt.Printf("[*] Loaded %d custom secret template(s)\n", len(extraSecretPatterns))
		}
	}
	rep := newReport(target, "file")
	if fi.IsDir() {
		fmt.Printf("[*] Recursively analyzing directory: %s\n", target)
		analyzeDirectory(target, rep)
	} else {
		ext := strings.ToLower(filepath.Ext(target))
		fmt.Printf("[*] File: %s\n", target)
		if archiveExt[ext] || isZip(target) {
			analyzeArchive(target, rep)
		} else {
			analyzeSingleFile(target, rep)
		}
	}
	rep.print()
	if jsonOut != "" {
		writeJSON(rep, jsonOut)
	}
	return 0
}

func isZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}
	return magic[0] == 'P' && magic[1] == 'K'
}

// ===========================================================================
//  update-templates
// ===========================================================================

func updateTemplates() int {
	os.MkdirAll(hakscanHome(), 0755)
	fmt.Println("[*] Downloading community YAML templates (MIT, (c) ProjectDiscovery - see NOTICE)...")
	tmp := filepath.Join(os.TempDir(), "hakscan_templates.zip")
	req, _ := http.NewRequest("GET", nucleiTemplatesZip, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := (&http.Client{Timeout: 180 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Download failed: %v\n", err)
		return 1
	}
	out, err := os.Create(tmp)
	if err != nil {
		resp.Body.Close()
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return 1
	}
	io.Copy(out, resp.Body)
	resp.Body.Close()
	out.Close()
	defer os.Remove(tmp)

	staging := filepath.Join(hakscanHome(), "_staging")
	os.RemoveAll(staging)
	if err := unzipSafe(tmp, staging); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Extraction failed: %v\n", err)
		return 1
	}
	extracted := filepath.Join(staging, "nuclei-templates-main")
	if st, e := os.Stat(extracted); e != nil || !st.IsDir() {
		entries, _ := os.ReadDir(staging)
		for _, en := range entries {
			if en.IsDir() {
				extracted = filepath.Join(staging, en.Name())
				break
			}
		}
	}
	os.RemoveAll(nucleiTemplatesDir())
	if err := os.Rename(extracted, nucleiTemplatesDir()); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return 1
	}
	os.RemoveAll(staging)
	count := 0
	filepath.Walk(nucleiTemplatesDir(), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			e := strings.ToLower(filepath.Ext(p))
			if e == ".yaml" || e == ".yml" {
				count++
			}
		}
		return nil
	})
	fmt.Printf("[*] %d templates installed in %s\n", count, nucleiTemplatesDir())
	fmt.Println("    Templates (c) ProjectDiscovery, MIT license.")
	fmt.Println("    Run them with:  hakscan -t auto https://target.com")
	return 0
}

func unzipSafe(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	destAbs, _ := filepath.Abs(dest)
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		ta, _ := filepath.Abs(target)
		if !strings.HasPrefix(ta, destAbs+string(os.PathSeparator)) && ta != destAbs {
			return fmt.Errorf("unsafe path: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		rc, e := f.Open()
		if e != nil {
			return e
		}
		w, e := os.Create(target)
		if e != nil {
			rc.Close()
			return e
		}
		io.Copy(w, io.LimitReader(rc, maxMember))
		w.Close()
		rc.Close()
	}
	return nil
}

// ===========================================================================
//  helpers + CLI
// ===========================================================================

func joinURL(base, p string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return base + p
	}
	ref, err := url.Parse(p)
	if err != nil {
		return base + p
	}
	return bu.ResolveReference(ref).String()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func joinSorted(m map[string]bool, limit int) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	return strings.Join(keys, ", ")
}

func popOpt(args *[]string, names ...string) string {
	a := *args
	for _, name := range names {
		for i := 0; i < len(a); i++ {
			if a[i] == name && i+1 < len(a) {
				val := a[i+1]
				a = append(a[:i], a[i+2:]...)
				*args = a
				return val
			}
		}
	}
	return ""
}

func popFlag(args *[]string, names ...string) bool {
	a := *args
	hit := false
	for _, name := range names {
		out := a[:0]
		for _, x := range a {
			if x == name {
				hit = true
				continue
			}
			out = append(out, x)
		}
		a = out
	}
	*args = a
	return hit
}

const helpText = `Hakscan ` + version + ` - web vulnerability scanner & file analyzer (native binary)

USAGE
  hakscan https://target.com                 web scan
  hakscan -u "https://t.com/p?id=1" --json r.json
  hakscan --passive https://target.com       no active injection tests
  hakscan -t auto https://target.com         run community YAML templates
  hakscan -t dir/ https://target.com         run custom/YAML templates in a dir
  hakscan -l targets.txt                     scan many targets from a file
  hakscan app.apk                            analyze a file (APK/ZIP/JAR/bin)
  hakscan ./dir/                             analyze a directory
  hakscan app.apk -t dir/                    + custom secret templates
  hakscan update-templates                   download community YAML templates
  hakscan version | -h

Authorized targets only. Scanning without permission is illegal.`

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(helpText)
		return
	}
	switch args[0] {
	case "version", "-version", "--version":
		fmt.Printf("Hakscan v%s\n", version)
		return
	case "update-templates", "update", "ut":
		os.Exit(updateTemplates())
	}

	jsonOut := popOpt(&args, "--json", "-o")
	delayStr := popOpt(&args, "--delay")
	templates := popOpt(&args, "-t", "--templates")
	passive := popFlag(&args, "--passive")
	listFile := popOpt(&args, "-l", "-list", "--list")
	target := popOpt(&args, "-u", "--url")

	delay := 300 * time.Millisecond
	if delayStr != "" {
		if d, err := time.ParseDuration(delayStr + "ms"); err == nil {
			delay = d
		}
	}

	if listFile != "" {
		data, err := os.ReadFile(listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot read list %s: %v\n", listFile, err)
			os.Exit(2)
		}
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			rep := newWebScanner(t, delay, templates, !passive).run()
			rep.print()
			if jsonOut != "" {
				writeJSON(rep, jsonOut)
			}
		}
		return
	}

	if len(args) > 0 && args[0] == "file" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "[!] usage: hakscan file <path>")
			os.Exit(2)
		}
		os.Exit(analyzeFileTarget(args[1], jsonOut, templates))
	}

	if target == "" {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				target = a
				break
			}
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "[!] No target. See: hakscan -h")
		os.Exit(2)
	}

	if _, err := os.Stat(target); err == nil {
		os.Exit(analyzeFileTarget(target, jsonOut, templates))
	}

	rep := newWebScanner(target, delay, templates, !passive).run()
	rep.print()
	if jsonOut != "" {
		writeJSON(rep, jsonOut)
	}
}
