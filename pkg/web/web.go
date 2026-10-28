package web

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/slayzbsss/Hakscan/pkg/httpx"
	"github.com/slayzbsss/Hakscan/pkg/output"
	"github.com/slayzbsss/Hakscan/pkg/templates"
	"github.com/slayzbsss/Hakscan/pkg/update"
	"gopkg.in/yaml.v3"
)

const (
	xssMark    = "hkxss9173<svg/onload=1>"
	redirProbe = "https://example.org/hk-redir-probe"
	evilHost   = "hakscan-evil.example"
)

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

type WebScanner struct {
	target    string
	delay     time.Duration
	templates string
	active    bool
	report    *output.Report
	tech      map[string]bool
}

func NewWebScanner(target string, delay time.Duration, templates string, active bool) *WebScanner {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	return &WebScanner{target: target, delay: delay, templates: templates, active: active,
		report: output.NewReport(target, "web"), tech: map[string]bool{}}
}

func (w *WebScanner) sleep() {
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
}

func (w *WebScanner) Run() *output.Report {
	fmt.Fprintln(os.Stderr, "[!] Authorized targets only. Scanning without permission is illegal.")
	fmt.Printf("[*] Initial request -> %s\n", w.target)
	base := httpx.DoHTTP(w.target, "GET", nil, true)
	if base == nil {
		w.report.Add("Target unreachable", "info", "No valid HTTP response.")
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

func (w *WebScanner) checkHeaders(r *httpx.Resp) {
	for _, sh := range secHeaders {
		if _, ok := r.Headers[sh.h]; ok {
			continue
		}
		if sh.h == "x-frame-options" && strings.Contains(r.Headers["content-security-policy"], "frame-ancestors") {
			continue
		}
		w.report.Add("Missing security header: "+sh.h, sh.sev, sh.msg)
	}
	for _, h := range infoHeaders {
		if v := strings.TrimSpace(r.Headers[h]); v != "" {
			w.report.Add("Information disclosure: "+h, "info", "Reveals server technology/version.", "", h+": "+v)
		}
	}
}

func (w *WebScanner) checkCookies(r *httpx.Resp) {
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
		w.report.Add("Insecure cookie", "low", "Missing attributes: "+strings.Join(miss, ", ")+" - session theft / CSRF risk.", "", ev)
	}
}

func (w *WebScanner) checkTLS(rawurl string) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return
	}
	if u.Scheme != "https" {
		w.report.Add("Unencrypted HTTP service", "medium", "Traffic travels in clear text (interception possible).")
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
			w.report.Add("TLS certificate validation failed", "high", "Invalid/self-signed/hostname-mismatched certificate: "+err.Error())
		} else {
			w.report.Add("TLS handshake error", "medium", err.Error())
		}
		return
	}
	defer conn.Close()
	st := conn.ConnectionState()
	switch st.Version {
	case tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11:
		w.report.Add("Obsolete TLS protocol", "medium", "Server negotiates an old TLS/SSL version.", "", tlsName(st.Version))
	}
	if len(st.PeerCertificates) > 0 {
		exp := st.PeerCertificates[0].NotAfter
		days := int(time.Until(exp).Hours() / 24)
		if days < 0 {
			w.report.Add("Expired TLS certificate", "high", fmt.Sprintf("Expired %d days ago.", -days), "", exp.String())
		} else if days < 15 {
			w.report.Add("TLS certificate near expiry", "low", fmt.Sprintf("Expires in %d days.", days), "", exp.String())
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
		r := httpx.DoHTTP(rawurl, "GET", map[string]string{"Origin": origin}, true)
		w.sleep()
		if r == nil {
			continue
		}
		acao := r.Headers["access-control-allow-origin"]
		acac := strings.ToLower(r.Headers["access-control-allow-credentials"])
		if acao == origin && origin == "null" {
			w.report.Add("CORS allows null origin", "medium", "ACAO reflects 'null' - exploitable via sandboxed iframe.", "", "ACAO="+acao+" ACAC="+acac)
		} else if acao == origin {
			sev := "medium"
			if acac == "true" {
				sev = "high"
			}
			w.report.Add("CORS reflects arbitrary origin", sev, "Server echoes attacker Origin in ACAO.", "", "ACAO="+acao+" ACAC="+acac)
		} else if acao == "*" && acac == "true" {
			w.report.Add("CORS wildcard with credentials", "medium", "ACAO=* together with Allow-Credentials=true (invalid/risky).")
		}
	}
}

func (w *WebScanner) checkMethods(rawurl string) {
	r := httpx.DoHTTP(rawurl, "OPTIONS", nil, true)
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
			w.report.Add("Risky HTTP method allowed: "+m, sev, "May allow content modification or Cross-Site Tracing.", "", "Allow: "+r.Headers["allow"])
		}
	}
}

func (w *WebScanner) fingerprint(r *httpx.Resp) {
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
		w.report.Add("Technology fingerprint", "info", "Detected stack - useful for targeted testing.", "", strings.Join(names, ", "))
	}
}

func (w *WebScanner) checkStacktrace(r *httpx.Resp) {
	low := strings.ToLower(r.Body)
	for _, s := range stacktraceSigns {
		if strings.Contains(low, s.sig) {
			w.report.Add("Verbose error / debug output ("+s.label+")", "medium", "Stack traces or debug pages can leak paths, versions and logic.", "", s.sig)
			return
		}
	}
}

var mixedRe = regexp.MustCompile(`(?i)(?:src|href|action)=["']?(http://[^"'>\s]+)`)

func (w *WebScanner) checkMixedContent(r *httpx.Resp) {
	if !strings.HasPrefix(r.URL, "https://") {
		return
	}
	m := mixedRe.FindAllStringSubmatch(r.Body, -1)
	if len(m) > 0 {
		w.report.Add("Mixed content", "low", fmt.Sprintf("%d resource(s) loaded over plain HTTP on an HTTPS page.", len(m)), "", m[0][1])
	}
}

var formRe = regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)

var pwRe = regexp.MustCompile(`(?i)type=["']?password`)

var actionRe = regexp.MustCompile(`(?i)action=["']?([^"'>\s]+)`)

var csrfRe = regexp.MustCompile(`(?i)csrf|token|authenticity`)

func (w *WebScanner) checkInsecureForms(r *httpx.Resp) {
	for _, form := range formRe.FindAllString(r.Body, -1) {
		if !pwRe.MatchString(form) {
			continue
		}
		act := ""
		if m := actionRe.FindStringSubmatch(form); m != nil {
			act = m[1]
		}
		if strings.HasPrefix(act, "http://") {
			w.report.Add("Password form submits over HTTP", "high", "Credentials sent in clear text.", "", act)
		} else if !csrfRe.MatchString(form) {
			w.report.Add("Form without apparent CSRF token", "low", "A sensitive form has no visible CSRF token field.")
			break
		}
	}
}

func (w *WebScanner) checkHostHeader(rawurl string) {
	r := httpx.DoHTTP(rawurl, "GET", map[string]string{"Host": evilHost}, false)
	w.sleep()
	if r == nil {
		return
	}
	if strings.Contains(r.Headers["location"], evilHost) {
		w.report.Add("Host header injection (redirect)", "medium", "Spoofed Host header is reflected in the redirect Location.", "", "Location: "+r.Headers["location"])
	} else if strings.Contains(r.Body, evilHost) {
		w.report.Add("Host header reflected in body", "low", "Spoofed Host appears in the response body (cache poisoning risk).")
	}
}

func (w *WebScanner) checkSensitivePaths(base string) {
	fmt.Println("[*] Probing for exposed sensitive files/paths")
	for _, p := range sensitivePaths {
		r := httpx.DoHTTP(joinURL(base, p), "GET", nil, true)
		w.sleep()
		if r == nil || r.Status != 200 || strings.TrimSpace(r.Body) == "" {
			continue
		}
		snippet := truncate(strings.ReplaceAll(strings.TrimSpace(r.Body), "\n", " "), 120)
		if strings.HasSuffix(p, "/") {
			if strings.Contains(strings.ToLower(r.Body), "index of /") {
				w.report.Add("Directory listing enabled: "+p, "medium", "Server exposes the folder contents.", "", snippet)
			}
			continue
		}
		sev := "high"
		if infoPaths[p] {
			sev = "info"
		}
		w.report.Add("Exposed resource: "+p, sev, "Potentially sensitive file publicly accessible.", "", "HTTP 200 - "+snippet)
	}
}

var envRe = regexp.MustCompile(`(?m)^[A-Z0-9_]+\s*=`)

func (w *WebScanner) checkVCS(base string) {
	r := httpx.DoHTTP(joinURL(base, "/.git/config"), "GET", nil, true)
	w.sleep()
	if r != nil && r.Status == 200 && strings.Contains(r.Body, "[core]") {
		w.report.Add("Git repository exposed", "high", "/.git/config is readable - full source history may be downloadable.", "", truncate(strings.ReplaceAll(strings.TrimSpace(r.Body), "\n", " "), 120))
	}
	r = httpx.DoHTTP(joinURL(base, "/.env"), "GET", nil, true)
	w.sleep()
	if r != nil && r.Status == 200 && envRe.MatchString(r.Body) {
		w.report.Add(".env file exposed", "critical", "Environment file with configuration/secrets is publicly readable.", "", truncate(strings.ReplaceAll(strings.TrimSpace(r.Body), "\n", " "), 120))
	}
}

var slugRe = regexp.MustCompile(`"slug":"([^"]+)"`)

func (w *WebScanner) checkCMS(base string) {
	if !w.tech["WordPress"] {
		return
	}
	fmt.Println("[*] WordPress detected - running CMS checks")
	r := httpx.DoHTTP(joinURL(base, "/wp-json/wp/v2/users"), "GET", nil, true)
	w.sleep()
	if r != nil && r.Status == 200 && strings.Contains(r.Body, `"slug"`) {
		var names []string
		for _, m := range slugRe.FindAllStringSubmatch(r.Body, 10) {
			names = append(names, m[1])
		}
		w.report.Add("WordPress user enumeration (REST API)", "medium", "/wp-json/wp/v2/users exposes usernames.", "", strings.Join(names, ", "))
	}
	r = httpx.DoHTTP(joinURL(base, "/xmlrpc.php"), "GET", nil, true)
	w.sleep()
	if r != nil && (r.Status == 200 || r.Status == 405) {
		w.report.Add("WordPress xmlrpc.php reachable", "low", "xmlrpc.php can be abused for brute force / pingback DDoS.")
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
		r := httpx.DoHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil && strings.Contains(r.Body, xssMark) {
			w.report.Add("Reflected XSS", "high", "Parameter '"+v[0]+"' is reflected unescaped into the response.", v[0], v[1])
		}
	}
	for _, v := range w.variants(rawurl, "hk'\"`)", nil) {
		r := httpx.DoHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil {
			low := strings.ToLower(r.Body)
			for _, sig := range sqlErrors {
				if strings.Contains(low, sig) {
					w.report.Add("SQL error triggered (possible SQLi)", "high", "Parameter '"+v[0]+"' triggers a database error.", v[0], sig)
					break
				}
			}
		}
	}
	for _, s := range ssti {
		for _, v := range w.variants(rawurl, s.payload, nil) {
			r := httpx.DoHTTP(v[1], "GET", nil, true)
			w.sleep()
			if r != nil && strings.Contains(r.Body, s.expect) && !strings.Contains(r.Body, s.payload) {
				w.report.Add("Server-side template injection (SSTI)", "high", "Parameter '"+v[0]+"': '"+s.payload+"' evaluated to '"+s.expect+"'.", v[0], s.payload+" -> "+s.expect)
			}
		}
	}
	for _, v := range w.variants(rawurl, "../../../../../../etc/passwd", nil) {
		r := httpx.DoHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil && strings.Contains(r.Body, "root:x:0:0:") {
			w.report.Add("Local file inclusion / path traversal", "critical", "Parameter '"+v[0]+"' reads arbitrary local files.", v[0], "root:x:0:0: found")
		}
	}
	cmdRe := regexp.MustCompile(`uid=\d+\(.+?\) gid=\d+\(`)
	for _, v := range w.variants(rawurl, ";id", nil) {
		r := httpx.DoHTTP(v[1], "GET", nil, true)
		w.sleep()
		if r != nil && cmdRe.MatchString(r.Body) {
			w.report.Add("OS command injection", "critical", "Parameter '"+v[0]+"' executes shell commands.", v[0], "uid=... gid=... found")
		}
	}
	for _, v := range w.variants(rawurl, "hk%0d%0aHakscan-Injected:1", nil) {
		r := httpx.DoHTTP(v[1], "GET", nil, false)
		w.sleep()
		if r != nil {
			if _, ok := r.Headers["hakscan-injected"]; ok {
				w.report.Add("CRLF / HTTP response header injection", "high", "Parameter '"+v[0]+"' injects response headers.", v[0], "Hakscan-Injected header reflected")
			}
		}
	}
	for _, v := range w.variants(rawurl, redirProbe, redirectParams) {
		r := httpx.DoHTTP(v[1], "GET", nil, false)
		w.sleep()
		if r != nil && strings.Contains(r.Headers["location"], "example.org/hk-redir-probe") {
			w.report.Add("Open redirect", "medium", "Parameter '"+v[0]+"' controls an external redirect.", v[0], v[1]+" -> "+r.Headers["location"])
		}
	}
}

// ===========================================================================
//  Templates: custom JSON + official nuclei YAML
// ===========================================================================

func (w *WebScanner) runTemplates(base string) {
	root := w.templates
	if root == "auto" || root == "nuclei" {
		root = update.NucleiTemplatesDir()
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		w.report.Add("Template directory not found", "info", root)
		if root == update.NucleiTemplatesDir() {
			w.report.Add("Hint", "info", "Run 'hakscan update-templates' first.")
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

func (w *WebScanner) runJSONTemplate(origin string, tpl map[string]interface{}, name string) {
	path, _ := tpl["path"].(string)
	if path == "" {
		path = "/"
	}
	method, _ := tpl["method"].(string)
	if method == "" {
		method = "GET"
	}
	r := httpx.DoHTTP(joinURL(origin, path), strings.ToUpper(method), nil, true)
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
			hay = templates.HeaderString(r)
		}
		switch m["type"] {
		case "status":
			results = append(results, templates.ContainsInt(templates.AsInts(m["values"]), r.Status))
		case "word":
			vals := templates.AsStrings(m["values"])
			all, _ := m["all"].(bool)
			results = append(results, templates.MatchWords(hay, vals, all))
		case "regex":
			results = append(results, templates.MatchRegex(hay, templates.AsStrings(m["values"]), false, false))
		default:
			results = append(results, false)
		}
	}
	if len(results) == 0 {
		return
	}
	ok := templates.Reduce(results, cond == "and")
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
		w.report.Add(title, sev, desc, path, name)
	}
}

func (w *WebScanner) runNucleiTemplates(origin string, files []string) {
	if len(files) > templates.MaxNuclei {
		fmt.Printf("[!] %d templates found; limiting to %d. Point -t at a subfolder to narrow scope.\n", len(files), templates.MaxNuclei)
		files = files[:templates.MaxNuclei]
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
	w.report.Add("YAML templates executed", "info",
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
	paths := templates.AsStrings(block["path"])
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
		r := httpx.DoHTTP(u, strings.ToUpper(method), nil, true)
		w.sleep()
		if r == nil {
			continue
		}
		ran = true
		if templates.NucleiMatch(r, matchers, cond) {
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
			w.report.Add(name, sev, truncate(strings.TrimSpace(desc), 200), u, id)
			return 1
		}
	}
	if ran {
		return 0
	}
	return -1
}

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

const httpTimeout = 12 * time.Second
