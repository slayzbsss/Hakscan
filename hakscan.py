#!/usr/bin/env python3
"""
Hakscan - web vulnerability scanner and file analyzer.

Self-contained, pure-Python (standard library only): no installation, no
external dependencies.

Two engines under one command:

  * WEB       hakscan https://target.com
              hakscan -u "https://target.com/page?id=1" --json report.json
              Security headers, cookies, TLS/cert, CORS, HTTP methods,
              exposed sensitive files/dirs, directory listing, VCS exposure,
              technology fingerprinting, CMS checks, debug/stack-trace leaks,
              mixed content, insecure forms, host-header injection, and on
              parameters: reflected XSS, SQL errors, SSTI, LFI, command
              injection, CRLF, open redirect.
              Custom JSON detection templates:  -t my_templates/
              Official nuclei templates (YAML):  hakscan update-templates
                                                 hakscan -t auto https://target.com

  * FILES     hakscan app.apk
              hakscan ./my-project/
              APK/AAB/XAPK/IPA/JAR/WAR/ZIP, binaries, source code:
              built-in AndroidManifest.xml parser (debuggable, allowBackup,
              cleartext traffic, exported components, dangerous permissions,
              embedded API keys), secret/credential scanner, endpoint
              extraction.

WARNING: Use only against targets you own or are explicitly authorized to
         test (bug bounty program scope). Scanning without permission is
         illegal.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

VERSION = "3.0"
USER_AGENT = "Hakscan/3.0 (+authorized-security-testing)"
HTTP_TIMEOUT = 12
MAX_BODY = 500_000

HAKSCAN_HOME = os.path.expanduser("~/.hakscan")
NUCLEI_TEMPLATES_DIR = os.path.join(HAKSCAN_HOME, "nuclei-templates")
NUCLEI_TEMPLATES_ZIP = ("https://github.com/projectdiscovery/nuclei-templates"
                        "/archive/refs/heads/main.zip")

SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
          "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"


# ===========================================================================
#  Result model
# ===========================================================================

@dataclass
class Finding:
    title: str
    severity: str
    detail: str
    location: str = ""
    evidence: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            self.severity = "info"


@dataclass
class Report:
    target: str
    mode: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)

    def add(self, *a, **k):
        self.findings.append(Finding(*a, **k))

    def to_dict(self):
        return {"target": self.target, "mode": self.mode,
                "started_at": self.started_at,
                "findings": [asdict(f) for f in self.findings]}


def print_report(report: Report):
    findings = sorted(report.findings, key=lambda f: -SEVERITIES[f.severity])
    color = sys.stdout.isatty()
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(f"{s}:{counts[s]}" for s in
                        ("critical", "high", "medium", "low", "info") if s in counts)
    print("\n" + "=" * 74)
    print(f" Hakscan - {report.mode} - {report.target}")
    print(f" {len(findings)} finding(s)   {summary}")
    print("=" * 74)
    if not findings:
        print(" Nothing notable found.")
        return
    for f in findings:
        tag = f.severity.upper()
        if color:
            tag = f"{COLORS[f.severity]}{tag}{RESET}"
        print(f"\n[{tag}] {f.title}")
        print(f"    {f.detail}")
        if f.location:
            print(f"    location: {f.location}")
        if f.evidence:
            ev = f.evidence if len(f.evidence) <= 180 else f.evidence[:177] + "..."
            print(f"    evidence: {ev}")
    print()


def write_json(report: Report, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, ensure_ascii=False, indent=2)
    print(f"[*] JSON report written to {path}")


# ===========================================================================
#  Minimal HTTP client
# ===========================================================================

@dataclass
class Resp:
    status: int
    headers: dict
    body: str
    url: str


_opener = build_opener()
_no_redirect_opener = build_opener(type("_NR", (HTTPRedirectHandler,),
                                        {"redirect_request": lambda *a, **k: None})())


def http(url: str, method: str = "GET", extra_headers: dict | None = None,
         follow: bool = True) -> Resp | None:
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = Request(url, method=method, headers=headers)
    opener = _opener if follow else _no_redirect_opener
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as r:
            raw = r.read(MAX_BODY)
            body = raw.decode(r.headers.get_content_charset() or "utf-8", "replace")
            return Resp(r.status, {k.lower(): v for k, v in r.headers.items()}, body, r.geturl())
    except HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        body = ""
        try:
            body = e.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:
            pass
        return Resp(e.code, hdrs, body, url)
    except (URLError, socket.timeout, OSError, ValueError):
        return None


# ===========================================================================
#  WEB ENGINE - data
# ===========================================================================

SEC_HEADERS = {
    "strict-transport-security": ("medium", "HSTS missing: vulnerable to HTTP downgrade / MITM."),
    "content-security-policy": ("medium", "CSP missing: wider XSS/injection attack surface."),
    "x-content-type-options": ("low", "Missing: MIME-sniffing risk."),
    "x-frame-options": ("low", "Missing: clickjacking risk (or use CSP frame-ancestors)."),
    "referrer-policy": ("info", "Missing: URLs may leak via the Referer header."),
    "permissions-policy": ("info", "Missing: browser features are not restricted."),
    "cross-origin-opener-policy": ("info", "Missing: no cross-origin isolation (Spectre class)."),
    "cross-origin-resource-policy": ("info", "Missing: resources embeddable cross-origin."),
}

INFO_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-generator", "x-drupal-cache", "via", "x-runtime", "x-backend-server",
                "x-served-by", "x-amz-cf-id"]

SENSITIVE_PATHS = [
    # VCS / config
    "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore", "/.svn/entries",
    "/.hg/requires", "/.bzr/README",
    # env / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.dev",
    "/.aws/credentials", "/.npmrc", "/.dockercfg", "/.docker/config.json",
    "/id_rsa", "/.ssh/id_rsa", "/.ssh/authorized_keys", "/.netrc",
    # backups / dumps
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql",
    "/database.sql", "/www.zip", "/site.zip", "/web.zip", "/app.zip",
    "/wp-config.php.bak", "/wp-config.php~", "/config.php.bak", "/config.php~",
    "/.htaccess", "/.htpasswd", "/web.config",
    # info disclosure
    "/phpinfo.php", "/info.php", "/test.php", "/server-status", "/server-info",
    "/.DS_Store", "/package.json", "/composer.json", "/composer.lock",
    "/yarn.lock", "/Gemfile", "/Gemfile.lock", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml", "/.dockerenv", "/Jenkinsfile",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # app / admin
    "/.well-known/security.txt", "/sitemap.xml", "/robots.txt",
    "/admin/", "/administrator/", "/wp-login.php", "/wp-admin/",
    "/phpmyadmin/", "/pma/", "/adminer.php", "/.vscode/", "/.idea/workspace.xml",
    "/swagger.json", "/swagger-ui.html", "/api/swagger.json", "/openapi.json",
    "/graphql", "/actuator", "/actuator/env", "/actuator/health", "/metrics",
    "/.well-known/openid-configuration",
    # listable dirs
    "/.git/", "/backup/", "/backups/", "/uploads/", "/files/", "/tmp/",
]
INFO_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
              "/crossdomain.xml", "/clientaccesspolicy.xml", "/composer.json",
              "/package.json", "/requirements.txt", "/Gemfile",
              "/.well-known/openid-configuration"}

REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_url", "redirect_uri",
                   "return", "returnurl", "return_url", "dest", "destination",
                   "continue", "r", "u", "goto", "target", "link", "out", "to"}

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg_query()", "pg_exec()", "sqlite3::",
    "sqlstate[", "ora-01756", "ora-00933", "mysql_fetch", "mysqli_fetch",
    "psql: error", "syntax error at or near", "odbc microsoft access driver",
    "microsoft ole db provider for sql server", "unterminated quoted string",
    "supplied argument is not a valid mysql",
]

LFI_SIGNS = ["root:x:0:0:", "root:.*:0:0:", "[extensions]", "for 16-bit app support"]
STACKTRACE_SIGNS = [
    ("Python traceback", "traceback (most recent call last)"),
    ("Django debug page", "you're seeing this error because you have debug = true"),
    ("PHP error", "fatal error:"),
    ("PHP warning", "warning: "),
    ("Java stack trace", "at java."),
    ("Java/Spring error", "org.springframework."),
    ("ASP.NET error", "server error in '/' application"),
    ("Ruby/Rails error", "actioncontroller::"),
    ("Node.js stack trace", "at module._compile"),
    ("Stack trace", ".java:"),
]

XSS_MARK = "hkxss9173<svg/onload=1>"
SSTI_PAYLOADS = [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%=7*7%>", "49"),
                 ("#{7*7}", "49")]
REDIR_PROBE = "https://example.org/hk-redir-probe"
EVIL_HOST = "hakscan-evil.example"


class WebScanner:
    def __init__(self, target: str, delay: float, templates: str | None,
                 active: bool = True):
        if not urlparse(target).scheme:
            target = "https://" + target
        self.target = target
        self.delay = max(0.0, delay)
        self.templates = templates
        self.active = active
        self.report = Report(target=target, mode="web")
        self.tech: set = set()

    def _sleep(self):
        if self.delay:
            time.sleep(self.delay)

    def run(self) -> Report:
        sys.stderr.write("[!] Authorized targets only. Scanning without permission is illegal.\n")
        print(f"[*] Initial request -> {self.target}")
        base = http(self.target)
        if not base:
            self.report.add("Target unreachable", "info", "No valid HTTP response.")
            return self.report
        print(f"[*] HTTP {base.status} ({base.url})")
        self.check_headers(base)
        self.check_cookies(base)
        self.check_tls(base.url)
        self.check_cors(base.url)
        self.check_methods(base.url)
        self.fingerprint(base)
        self.check_stacktrace(base)
        self.check_mixed_content(base)
        self.check_insecure_forms(base)
        self.check_host_header_injection(base.url)
        self.check_sensitive_paths(base.url)
        self.check_vcs_exposure(base.url)
        self.check_cms(base.url)
        if self.active:
            self.check_params(self.target)
        if self.templates:
            self.run_templates(base.url)
        return self.report

    # --- passive ------------------------------------------------------------
    def check_headers(self, r: Resp):
        for h, (sev, msg) in SEC_HEADERS.items():
            if h in r.headers:
                continue
            if h == "x-frame-options" and "frame-ancestors" in r.headers.get("content-security-policy", ""):
                continue
            self.report.add(f"Missing security header: {h}", sev, msg)
        for h in INFO_HEADERS:
            if r.headers.get(h, "").strip():
                self.report.add(f"Information disclosure: {h}", "info",
                                "Reveals server technology/version.",
                                evidence=f"{h}: {r.headers[h]}")
        xss = r.headers.get("x-xss-protection", "")
        if xss and xss.strip().startswith("1"):
            self.report.add("Legacy X-XSS-Protection enabled", "info",
                            "This filter is deprecated and can introduce vulnerabilities.",
                            evidence=xss)

    def check_cookies(self, r: Resp):
        raw = r.headers.get("set-cookie")
        if not raw:
            return
        low = raw.lower()
        miss = [x for x in ("secure", "httponly", "samesite") if x not in low]
        if miss:
            self.report.add("Insecure cookie", "low",
                            "Missing attributes: " + ", ".join(miss) +
                            " - session theft / CSRF risk.", evidence=raw[:180])

    def check_tls(self, url: str):
        p = urlparse(url)
        if p.scheme != "https":
            self.report.add("Unencrypted HTTP service", "medium",
                            "Traffic travels in clear text (interception possible).")
            return
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((p.hostname, p.port or 443), timeout=HTTP_TIMEOUT) as s:
                with ctx.wrap_socket(s, server_hostname=p.hostname) as ss:
                    cert = ss.getpeercert()
                    proto = ss.version()
        except ssl.SSLCertVerificationError as e:
            self.report.add("TLS certificate validation failed", "high",
                            f"Invalid/self-signed/hostname-mismatched certificate: {e.verify_message}")
            return
        except (ssl.SSLError, OSError) as e:
            self.report.add("TLS handshake error", "medium", str(e))
            return
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            self.report.add("Obsolete TLS protocol", "medium",
                            f"Server negotiates {proto}.", evidence=proto)
        na = cert.get("notAfter") if cert else None
        if na:
            try:
                exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    self.report.add("Expired TLS certificate", "high",
                                    f"Expired {-days} days ago.", evidence=na)
                elif days < 15:
                    self.report.add("TLS certificate near expiry", "low",
                                    f"Expires in {days} days.", evidence=na)
            except ValueError:
                pass

    def check_cors(self, url: str):
        for origin in (f"https://{EVIL_HOST}", "null"):
            r = http(url, extra_headers={"Origin": origin})
            self._sleep()
            if not r:
                continue
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            if acao == origin and origin == "null":
                self.report.add("CORS allows null origin", "medium",
                                "ACAO reflects 'null' - exploitable via sandboxed iframe.",
                                evidence=f"ACAO={acao} ACAC={acac or 'absent'}")
            elif acao == origin:
                sev = "high" if acac == "true" else "medium"
                self.report.add("CORS reflects arbitrary origin", sev,
                                "Server echoes attacker Origin in ACAO" +
                                (" with credentials allowed." if acac == "true" else "."),
                                evidence=f"ACAO={acao} ACAC={acac or 'absent'}")
            elif acao == "*" and acac == "true":
                self.report.add("CORS wildcard with credentials", "medium",
                                "ACAO=* together with Allow-Credentials=true (invalid/risky).")

    def check_methods(self, url: str):
        r = http(url, method="OPTIONS")
        self._sleep()
        if r and r.headers.get("allow"):
            allowed = r.headers["allow"].upper()
            for m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"):
                if m in allowed:
                    sev = "medium" if m in ("PUT", "DELETE") else "low"
                    self.report.add(f"Risky HTTP method allowed: {m}", sev,
                                    "May allow content modification or Cross-Site Tracing.",
                                    evidence=f"Allow: {r.headers['allow']}")

    def fingerprint(self, r: Resp):
        checks = {
            "WordPress": "wp-content" in r.body or "wp-includes" in r.body,
            "Drupal": "drupal" in r.body.lower() or "x-drupal-cache" in r.headers,
            "Joomla": "joomla" in r.body.lower(),
            "Django": "csrftoken" in r.headers.get("set-cookie", "").lower(),
            "PHP": "php" in r.headers.get("x-powered-by", "").lower() or "phpsessid" in r.headers.get("set-cookie", "").lower(),
            "ASP.NET": "asp.net" in r.headers.get("x-powered-by", "").lower() or "asp.net_sessionid" in r.headers.get("set-cookie", "").lower(),
            "Java/JSP": "jsessionid" in r.headers.get("set-cookie", "").lower(),
            "Laravel": "laravel_session" in r.headers.get("set-cookie", "").lower(),
            "Express/Node": "express" in r.headers.get("x-powered-by", "").lower(),
        }
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.body, re.I)
        for name, hit in checks.items():
            if hit:
                self.tech.add(name)
        if self.tech:
            self.report.add("Technology fingerprint", "info",
                            "Detected stack - useful for targeted testing.",
                            evidence=", ".join(sorted(self.tech)) +
                            (f"; generator={m.group(1)}" if m else ""))

    def check_stacktrace(self, r: Resp):
        low = r.body.lower()
        for label, sig in STACKTRACE_SIGNS:
            if sig in low:
                self.report.add(f"Verbose error / debug output ({label})", "medium",
                                "Stack traces or debug pages can leak paths, versions and logic.",
                                evidence=sig)
                break

    def check_mixed_content(self, r: Resp):
        if not r.url.startswith("https://"):
            return
        res = re.findall(r'(?:src|href|action)=["\']?(http://[^"\'>\s]+)', r.body, re.I)
        if res:
            self.report.add("Mixed content", "low",
                            f"{len(res)} resource(s) loaded over plain HTTP on an HTTPS page.",
                            evidence=res[0])

    def check_insecure_forms(self, r: Resp):
        forms = re.findall(r'<form[^>]*>.*?</form>', r.body, re.I | re.S)
        for form in forms:
            has_pw = re.search(r'type=["\']?password', form, re.I)
            action = re.search(r'action=["\']?([^"\'>\s]+)', form, re.I)
            if has_pw:
                act = action.group(1) if action else ""
                if act.startswith("http://"):
                    self.report.add("Password form submits over HTTP", "high",
                                    "Credentials sent in clear text.", evidence=act)
                elif not re.search(r'csrf|token|authenticity', form, re.I):
                    self.report.add("Form without apparent CSRF token", "low",
                                    "A sensitive form has no visible CSRF token field.")
                    break

    def check_host_header_injection(self, url: str):
        r = http(url, extra_headers={"Host": EVIL_HOST}, follow=False)
        self._sleep()
        if not r:
            return
        loc = r.headers.get("location", "")
        if EVIL_HOST in loc:
            self.report.add("Host header injection (redirect)", "medium",
                            "Spoofed Host header is reflected in the redirect Location.",
                            evidence=f"Location: {loc}")
        elif EVIL_HOST in r.body:
            self.report.add("Host header reflected in body", "low",
                            "Spoofed Host appears in the response body (cache poisoning risk).")

    def check_sensitive_paths(self, base: str):
        print("[*] Probing for exposed sensitive files/paths")
        for path in SENSITIVE_PATHS:
            r = http(urljoin(base, path))
            self._sleep()
            if not r or r.status != 200 or not r.body.strip():
                continue
            snippet = r.body.strip().replace("\n", " ")[:120]
            if path.endswith("/"):
                if "index of /" in r.body.lower():
                    self.report.add(f"Directory listing enabled: {path}", "medium",
                                    "Server exposes the folder contents.", evidence=snippet)
                continue
            sev = "info" if path in INFO_PATHS else "high"
            if "phpinfo" in path and "phpinfo()" in r.body.lower():
                sev = "high"
            self.report.add(f"Exposed resource: {path}", sev,
                            "Potentially sensitive file publicly accessible.",
                            evidence=f"HTTP 200 - {snippet}")

    def check_vcs_exposure(self, base: str):
        r = http(urljoin(base, "/.git/config"))
        self._sleep()
        if r and r.status == 200 and "[core]" in r.body:
            self.report.add("Git repository exposed", "high",
                            "/.git/config is readable - full source history may be downloadable.",
                            evidence=r.body.strip().replace("\n", " ")[:120])
        r = http(urljoin(base, "/.env"))
        self._sleep()
        if r and r.status == 200 and re.search(r"(?mi)^[A-Z0-9_]+\s*=", r.body):
            self.report.add(".env file exposed", "critical",
                            "Environment file with configuration/secrets is publicly readable.",
                            evidence=r.body.strip().replace("\n", " ")[:120])

    def check_cms(self, base: str):
        if "WordPress" not in self.tech:
            return
        print("[*] WordPress detected - running CMS checks")
        r = http(urljoin(base, "/wp-json/wp/v2/users"))
        self._sleep()
        if r and r.status == 200 and '"slug"' in r.body:
            names = re.findall(r'"slug":"([^"]+)"', r.body)
            self.report.add("WordPress user enumeration (REST API)", "medium",
                            "/wp-json/wp/v2/users exposes usernames.",
                            evidence=", ".join(names[:10]))
        r = http(urljoin(base, "/xmlrpc.php"))
        self._sleep()
        if r and r.status in (200, 405):
            self.report.add("WordPress xmlrpc.php reachable", "low",
                            "xmlrpc.php can be abused for brute force / pingback DDoS.")

    # --- active (parameter injections) --------------------------------------
    def _variants(self, url: str, payload: str, only=None):
        p = urlparse(url)
        params = parse_qsl(p.query, keep_blank_values=True)
        for i, (k, _v) in enumerate(params):
            if only and k.lower() not in only:
                continue
            new = list(params)
            new[i] = (k, payload)
            yield k, urlunparse(p._replace(query=urlencode(new)))

    def check_params(self, url: str):
        if not urlparse(url).query:
            print("[*] No query parameters (?x=y): active injection tests skipped")
            return
        print("[*] Active parameter tests (XSS / SQLi / SSTI / LFI / cmd / CRLF / redirect)")
        # Reflected XSS
        for key, variant in self._variants(url, XSS_MARK):
            r = http(variant); self._sleep()
            if r and XSS_MARK in r.body:
                self.report.add("Reflected XSS", "high",
                                f"Parameter '{key}' is reflected unescaped into the response.",
                                location=key, evidence=variant)
        # SQL errors
        for key, variant in self._variants(url, "hk'\"`)"):
            r = http(variant); self._sleep()
            if r:
                low = r.body.lower()
                for sig in SQL_ERRORS:
                    if sig in low:
                        self.report.add("SQL error triggered (possible SQLi)", "high",
                                        f"Parameter '{key}' triggers a database error.",
                                        location=key, evidence=sig)
                        break
        # SSTI
        for payload, expect in SSTI_PAYLOADS:
            for key, variant in self._variants(url, payload):
                r = http(variant); self._sleep()
                if r and expect in r.body and payload not in r.body:
                    self.report.add("Server-side template injection (SSTI)", "high",
                                    f"Parameter '{key}': '{payload}' evaluated to '{expect}'.",
                                    location=key, evidence=f"{payload} -> {expect}")
        # LFI / path traversal
        for key, variant in self._variants(url, "../../../../../../etc/passwd"):
            r = http(variant); self._sleep()
            if r and ("root:x:0:0:" in r.body or re.search(r"root:.*:0:0:", r.body)):
                self.report.add("Local file inclusion / path traversal", "critical",
                                f"Parameter '{key}' reads arbitrary local files.",
                                location=key, evidence="root:x:0:0: found")
        # Command injection (read-only probe)
        for key, variant in self._variants(url, ";id"):
            r = http(variant); self._sleep()
            if r and re.search(r"uid=\d+\(.+?\) gid=\d+\(", r.body):
                self.report.add("OS command injection", "critical",
                                f"Parameter '{key}' executes shell commands.",
                                location=key, evidence="uid=... gid=... found")
        # CRLF / header injection
        crlf = "hk%0d%0aHakscan-Injected:1"
        for key, variant in self._variants(url, crlf):
            r = http(variant, follow=False); self._sleep()
            if r and "hakscan-injected" in {k.lower() for k in r.headers}:
                self.report.add("CRLF / HTTP response header injection", "high",
                                f"Parameter '{key}' injects response headers.",
                                location=key, evidence="Hakscan-Injected header reflected")
        # Open redirect (only redirect-looking params)
        for key, variant in self._variants(url, REDIR_PROBE, only=REDIRECT_PARAMS):
            r = http(variant, follow=False); self._sleep()
            loc = r.headers.get("location", "") if r else ""
            if "example.org/hk-redir-probe" in loc:
                self.report.add("Open redirect", "medium",
                                f"Parameter '{key}' controls an external redirect.",
                                location=key, evidence=f"{variant} -> {loc}")

    # --- templates: custom JSON + official nuclei YAML ----------------------
    MAX_NUCLEI = 4000

    def run_templates(self, base: str):
        root = self.templates
        if root in ("auto", "nuclei"):
            root = NUCLEI_TEMPLATES_DIR
        if not os.path.isdir(root):
            self.report.add("Template directory not found", "info", root)
            if root == NUCLEI_TEMPLATES_DIR:
                self.report.add("Hint", "info", "Run 'hakscan update-templates' first.")
            return
        json_files, yaml_files = [], []
        for r, _d, fs in os.walk(root):
            for f in fs:
                p = os.path.join(r, f)
                if f.endswith(".json"):
                    json_files.append(p)
                elif f.endswith((".yaml", ".yml")):
                    yaml_files.append(p)
        pp = urlparse(base)
        origin = f"{pp.scheme}://{pp.netloc}"
        print(f"[*] Templates: {len(json_files)} custom (JSON), {len(yaml_files)} nuclei (YAML)")
        for fp in json_files:
            try:
                with open(fp, encoding="utf-8") as fh:
                    tpl = json.load(fh)
            except (OSError, json.JSONDecodeError) as e:
                self.report.add("Unreadable template", "info", f"{fp}: {e}")
                continue
            self._run_one_template(origin, tpl, os.path.basename(fp))
        if yaml_files:
            self._run_nuclei_templates(origin, yaml_files)

    def _run_nuclei_templates(self, origin: str, files: list):
        try:
            import yaml
        except ImportError:
            self.report.add("nuclei templates skipped", "info",
                            "PyYAML not available; install it to run YAML templates.")
            return
        if len(files) > self.MAX_NUCLEI:
            print(f"[!] {len(files)} templates found; limiting to {self.MAX_NUCLEI}. "
                  "Point -t at a subfolder to narrow the scope.")
            files = files[:self.MAX_NUCLEI]
        run = matched = skipped = 0
        for fp in files:
            try:
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    tpl = yaml.safe_load(fh)
            except Exception:
                skipped += 1
                continue
            if not isinstance(tpl, dict):
                skipped += 1
                continue
            res = self._run_one_nuclei(origin, tpl)
            if res is None:
                skipped += 1
            else:
                run += 1
                matched += 1 if res else 0
            self._sleep()
        self.report.add("nuclei templates executed", "info",
                        f"{run} run, {matched} matched, {skipped} skipped "
                        "(unsupported construct or parse error).")

    def _run_one_nuclei(self, origin: str, tpl: dict):
        """Run a single nuclei HTTP template (supported subset).
        Returns True (match), False (ran, no match) or None (unsupported)."""
        info = tpl.get("info") or {}
        reqs = tpl.get("http") or tpl.get("requests")
        if not isinstance(reqs, list) or not reqs:
            return None
        block = reqs[0]
        if not isinstance(block, dict) or "raw" in block:
            return None
        paths = block.get("path")
        matchers = block.get("matchers")
        if not isinstance(paths, list) or not paths or not isinstance(matchers, list) or not matchers:
            return None
        for m in matchers:
            if not isinstance(m, dict) or m.get("type") not in ("word", "status", "regex"):
                return None
        method = (block.get("method") or "GET").upper()
        cond = (block.get("matchers-condition") or "or").lower()
        ran = False
        for raw_path in paths[:5]:
            url = str(raw_path).replace("{{BaseURL}}", origin).replace("{{Hostname}}", urlparse(origin).netloc)
            if "{{" in url:
                return None
            r = http(url, method=method)
            self._sleep()
            if not r:
                continue
            ran = True
            if self._nuclei_match(r, matchers, cond):
                self.report.add(info.get("name") or tpl.get("id", "nuclei template"),
                                info.get("severity", "info"),
                                (str(info.get("description") or "nuclei template matched.")).strip()[:200],
                                location=url, evidence=tpl.get("id", ""))
                return True
        return False if ran else None

    def _part(self, r: Resp, part: str) -> str:
        hdr = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        if part == "header":
            return hdr
        if part in ("all", "raw", "response"):
            return f"HTTP {r.status}\n{hdr}\n\n{r.body}"
        return r.body

    def _nuclei_match(self, r: Resp, matchers: list, cond: str) -> bool:
        results = []
        for m in matchers:
            t = m.get("type")
            neg = bool(m.get("negative"))
            ci = bool(m.get("case-insensitive"))
            hay = self._part(r, m.get("part", "body"))
            if ci:
                hay = hay.lower()
            mc = (m.get("condition") or "or").lower()
            res = False
            try:
                if t == "word":
                    words = [str(w).lower() if ci else str(w) for w in m.get("words", [])]
                    res = all(w in hay for w in words) if mc == "and" else any(w in hay for w in words)
                elif t == "status":
                    res = r.status in (m.get("status") or [])
                elif t == "regex":
                    flags = re.I if ci else 0
                    pats = m.get("regex", [])
                    res = (all(re.search(p, hay, flags) for p in pats) if mc == "and"
                           else any(re.search(p, hay, flags) for p in pats))
            except re.error:
                res = False
            results.append((not res) if neg else res)
        if not results:
            return False
        return all(results) if cond == "and" else any(results)

    def _run_one_template(self, base: str, tpl: dict, name: str):
        r = http(urljoin(base, tpl.get("path", "/")), method=tpl.get("method", "GET").upper())
        self._sleep()
        if not r:
            return
        cond = tpl.get("matchers-condition", "and").lower()
        results = []
        for mt in tpl.get("matchers", []):
            kind = mt.get("type")
            part = r.body if mt.get("part", "body") == "body" else str(r.headers)
            if kind == "status":
                results.append(r.status in mt.get("values", []))
            elif kind == "word":
                vals = mt.get("values", [])
                results.append(all(v in part for v in vals) if mt.get("all") else any(v in part for v in vals))
            elif kind == "regex":
                results.append(any(re.search(v, part) for v in mt.get("values", [])))
            else:
                results.append(False)
        ok = all(results) if cond == "and" else any(results)
        if ok and results:
            self.report.add(tpl.get("name", name), tpl.get("severity", "info"),
                            tpl.get("description", "Custom template matched."),
                            location=tpl.get("path", "/"), evidence=name)


# ===========================================================================
#  FILE ENGINE - secret scanner
# ===========================================================================

SECRET_PATTERNS = [
    ("Private key block (PEM)", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("AWS Access Key ID", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key", "high", re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth client", "medium", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
    ("GCP service account", "high", re.compile(r'"type"\s*:\s*"service_account"')),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("GitLab token", "high", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b")),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Slack webhook", "medium", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")),
    ("Discord webhook", "medium", re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+")),
    ("Discord bot token", "high", re.compile(r"\b[MNO][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b")),
    ("Telegram bot token", "medium", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("Stripe live key", "critical", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}")),
    ("Stripe restricted key", "high", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}")),
    ("Twilio SID", "medium", re.compile(r"\bAC[a-z0-9]{32}\b")),
    ("SendGrid API key", "high", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("Mailgun key", "high", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("Square access token", "high", re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b")),
    ("Heroku API key", "medium", re.compile(r"(?i)heroku.{0,15}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("npm token", "high", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI token", "high", re.compile(r"\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{50,}")),
    ("JWT", "low", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Firebase DB URL", "medium", re.compile(r"[a-z0-9.-]+\.firebaseio\.com")),
    ("Basic auth in URL", "high", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[A-Za-z0-9.-]+")),
    ("DB connection string", "high", re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]+")),
    ("Hardcoded secret (assignment)", "low",
     re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password|token|private[_-]?key|access[_-]?key)"
                r"['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
]

URL_PATTERN = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
IP_PATTERN = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")

DANGEROUS_PERMS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE", "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


def _mask(s: str) -> str:
    s = s.strip()
    return s[:4] + "..." if len(s) <= 12 else s[:6] + "..." + s[-4:]


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def extract_strings(data: bytes) -> str:
    return "\n".join(m.group(0).decode("ascii", "ignore") for m in _PRINTABLE_RUN.finditer(data))


def text_from_bytes(data: bytes) -> str:
    return extract_strings(data) if _looks_binary(data) else data.decode("utf-8", "replace")


def scan_text_for_secrets(text: str, location: str, report: Report, seen: set):
    for name, sev, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            key = (name, m.group(0)[:40], location)
            if key in seen:
                continue
            seen.add(key)
            report.add(f"Potential secret: {name}", sev,
                       "Possibly hardcoded credential/key.",
                       location=location, evidence=_mask(m.group(0)))


# ===========================================================================
#  Built-in AndroidManifest.xml (AXML) parser
# ===========================================================================

class AXMLParseError(Exception):
    pass


class AXMLParser:
    STRING_POOL = 0x0001
    START_ELEMENT = 0x0102
    UTF8_FLAG = 0x0100

    def __init__(self, data: bytes):
        self.data = data
        self.strings: list[str] = []
        self.elements: list[tuple[str, dict]] = []

    def parse(self):
        d = self.data
        if len(d) < 8 or struct.unpack_from("<H", d, 0)[0] != 0x0003:
            raise AXMLParseError("invalid AXML header")
        off, n = 8, len(d)
        while off + 8 <= n:
            ctype, _h, csize = struct.unpack_from("<HHI", d, off)
            if csize < 8 or off + csize > n:
                break
            if ctype == self.STRING_POOL:
                self._string_pool(off)
            elif ctype == self.START_ELEMENT:
                self._start_element(off)
            off += csize
        return self

    def _string_pool(self, off):
        d = self.data
        count, _s, flags, strings_start = struct.unpack_from("<IIII", d, off + 8)
        utf8 = bool(flags & self.UTF8_FLAG)
        offsets_base, data_base = off + 28, off + strings_start
        self.strings = []
        for i in range(count):
            so = struct.unpack_from("<I", d, offsets_base + i * 4)[0]
            try:
                self.strings.append(self._read_str(data_base + so, utf8))
            except Exception:
                self.strings.append("")

    def _read_str(self, p, utf8):
        d = self.data
        if utf8:
            p += 2 if d[p] & 0x80 else 1
            blen = d[p]
            if blen & 0x80:
                blen = ((blen & 0x7f) << 8) | d[p + 1]; p += 2
            else:
                p += 1
            return d[p:p + blen].decode("utf-8", "replace")
        ln = struct.unpack_from("<H", d, p)[0]
        if ln & 0x8000:
            ln = ((ln & 0x7fff) << 16) | struct.unpack_from("<H", d, p + 2)[0]; p += 4
        else:
            p += 2
        return d[p:p + ln * 2].decode("utf-16-le", "replace")

    def _str(self, idx):
        return self.strings[idx] if 0 <= idx < len(self.strings) else ""

    def _start_element(self, off):
        d = self.data
        name_idx = struct.unpack_from("<I", d, off + 20)[0]
        attr_start, _a, attr_count = struct.unpack_from("<HHH", d, off + 24)
        attrs, base = {}, off + 16 + attr_start
        for i in range(attr_count):
            a = base + i * 20
            if a + 20 > len(d):
                break
            _ns, aname, raw, _sz, dtype, ddata = struct.unpack_from("<IIIHxBI", d, a)
            attrs[self._str(aname)] = self._typed(raw, dtype, ddata)
        self.elements.append((self._str(name_idx), attrs))

    def _typed(self, raw, dtype, data):
        if raw != 0xFFFFFFFF:
            s = self._str(raw)
            if s:
                return s
        if dtype == 0x12:
            return "true" if data != 0 else "false"
        if dtype == 0x03:
            return self._str(data)
        return str(data)


# ===========================================================================
#  FILE ENGINE - archives, APK, directories
# ===========================================================================

ARCHIVE_EXT = {".apk", ".aab", ".xapk", ".ipa", ".jar", ".war", ".zip"}
MAX_MEMBER = 25 * 1024 * 1024


def analyze_manifest(data: bytes, report: Report):
    try:
        elements = AXMLParser(data).parse().elements
    except Exception as e:
        report.add("AndroidManifest not parsed", "info",
                   f"AXML parsing failed ({e}); string analysis only.",
                   location="AndroidManifest.xml")
        return
    perms = []
    for tag, attrs in elements:
        if tag == "application":
            if attrs.get("debuggable") == "true":
                report.add("Debuggable APK", "high",
                           'android:debuggable="true": debugging possible in production.',
                           location="application")
            if attrs.get("allowBackup") == "true":
                report.add("Backup allowed (allowBackup)", "low",
                           'android:allowBackup="true": data extractable via adb.',
                           location="application")
            if attrs.get("usesCleartextTraffic") == "true":
                report.add("Cleartext traffic allowed", "medium",
                           'android:usesCleartextTraffic="true": plain HTTP permitted.',
                           location="application")
            if attrs.get("testOnly") == "true":
                report.add("testOnly flag set", "low",
                           'android:testOnly="true": debug/test build.', location="application")
            if "networkSecurityConfig" in attrs:
                report.add("Network Security Config present", "info",
                           "Inspect it: may allow cleartext or custom CAs.", location="application")
        elif tag in ("activity", "service", "receiver", "provider"):
            if attrs.get("exported") == "true" and "permission" not in attrs:
                report.add(f"Exported component without permission: {tag}", "medium",
                           "Reachable by other apps with no protection.",
                           location=attrs.get("name", "?"))
        elif tag == "uses-permission":
            name = attrs.get("name", "")
            if name:
                perms.append(name)
        elif tag == "meta-data":
            val = attrs.get("value", "")
            nm = attrs.get("name", "")
            if re.match(r"AIza[0-9A-Za-z\-_]{35}", val) or "API_KEY" in nm.upper():
                report.add("Embedded API key in manifest meta-data", "high",
                           f"meta-data '{nm}' may hold an API key.",
                           location="meta-data", evidence=_mask(val) if val else nm)
    dangerous = sorted(set(perms) & DANGEROUS_PERMS)
    if dangerous:
        report.add(f"Dangerous permissions requested ({len(dangerous)})", "info",
                   "App requests sensitive permissions.", evidence=", ".join(dangerous[:12]))


def analyze_archive(path: str, report: Report):
    seen, urls, ips = set(), set(), set()
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        report.add("Unreadable archive", "info", "Not a valid ZIP.",
                   location=os.path.basename(path))
        return
    with zf:
        names = zf.namelist()
        for info in zf.infolist():
            if info.is_dir() or info.file_size > MAX_MEMBER:
                continue
            try:
                data = zf.read(info)
            except Exception:
                continue
            member = info.filename
            if os.path.basename(member) == "AndroidManifest.xml" and member.count("/") == 0:
                analyze_manifest(data, report)
            scan_text_for_secrets(text_from_bytes(data), member, report, seen)
            for m in URL_PATTERN.finditer(data):
                host = urlparse(m.group(0).decode("ascii", "ignore")).hostname
                if host and not host.endswith((".google.com", ".android.com", ".w3.org")) \
                        and "schemas.android.com" not in host:
                    urls.add(host)
            for m in IP_PATTERN.finditer(data):
                ip = m.group(0).decode()
                if not ip.startswith(("127.", "0.", "255.")):
                    ips.add(ip)
        if "classes.dex" in names:
            report.add("Android application (DEX present)", "info",
                       "classes.dex found in the archive.", location="classes.dex")
    if urls:
        report.add(f"Referenced network endpoints ({len(urls)})", "info",
                   "Domains extracted - recon / attack surface leads.",
                   evidence=", ".join(sorted(urls)[:15]))
    if ips:
        report.add(f"Hardcoded IP addresses ({len(ips)})", "info",
                   "IPs embedded in the app.", evidence=", ".join(sorted(ips)[:10]))


def analyze_single_file(path: str, report: Report):
    seen = set()
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_MEMBER)
    except OSError as e:
        report.add("Unreadable file", "info", str(e), location=path)
        return
    scan_text_for_secrets(text_from_bytes(data), os.path.basename(path), report, seen)


def analyze_directory(path: str, report: Report):
    seen = set()
    for root, _dirs, files in os.walk(path):
        if any(s in root for s in (".git", "node_modules", "__pycache__")):
            continue
        for fname in files:
            fp = os.path.join(root, fname)
            if os.path.splitext(fname)[1].lower() in ARCHIVE_EXT:
                analyze_archive(fp, report)
                continue
            try:
                if os.path.getsize(fp) > MAX_MEMBER:
                    continue
                with open(fp, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            scan_text_for_secrets(text_from_bytes(data), os.path.relpath(fp, path), report, seen)


def analyze_file_target(target: str, json_out: str | None) -> int:
    if not os.path.exists(target):
        sys.stderr.write(f"[!] Target not found: {target}\n")
        return 2
    report = Report(target=target, mode="file")
    if os.path.isdir(target):
        print(f"[*] Recursively analyzing directory: {target}")
        analyze_directory(target, report)
    else:
        ext = os.path.splitext(target)[1].lower()
        ftype = ""
        try:
            ftype = subprocess.run(["file", "-b", target], capture_output=True,
                                   text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        print(f"[*] File: {target}  ({ftype or 'unknown type'})")
        if ext in ARCHIVE_EXT or "Zip archive" in ftype or "Android" in ftype:
            analyze_archive(target, report)
        else:
            analyze_single_file(target, report)
    print_report(report)
    if json_out:
        write_json(report, json_out)
    return 0


# ===========================================================================
#  Official template management (nuclei-templates, MIT - ProjectDiscovery)
# ===========================================================================

def _safe_extract(zf: zipfile.ZipFile, dest: str):
    dest_abs = os.path.abspath(dest)
    for member in zf.namelist():
        target = os.path.abspath(os.path.join(dest, member))
        if not target.startswith(dest_abs + os.sep) and target != dest_abs:
            raise ValueError(f"unsafe path in archive: {member}")
    zf.extractall(dest)


def update_templates() -> int:
    """Download the official nuclei-templates into ~/.hakscan/nuclei-templates.

    These templates are the work of ProjectDiscovery, distributed under the
    MIT license; Hakscan only downloads and runs them locally.
    """
    os.makedirs(HAKSCAN_HOME, exist_ok=True)
    tmpzip = os.path.join(tempfile.gettempdir(), "hakscan_templates.zip")
    print("[*] Downloading the official nuclei-templates (MIT, (c) ProjectDiscovery)...")
    try:
        req = Request(NUCLEI_TEMPLATES_ZIP, headers={"User-Agent": USER_AGENT})
        with _opener.open(req, timeout=180) as r, open(tmpzip, "wb") as fh:
            shutil.copyfileobj(r, fh)
    except (URLError, OSError) as e:
        sys.stderr.write(f"[!] Download failed: {e}\n")
        return 1
    staging = os.path.join(HAKSCAN_HOME, "_staging")
    shutil.rmtree(staging, ignore_errors=True)
    try:
        with zipfile.ZipFile(tmpzip) as z:
            _safe_extract(z, staging)
    except (zipfile.BadZipFile, ValueError) as e:
        sys.stderr.write(f"[!] Extraction failed: {e}\n")
        return 1
    finally:
        os.remove(tmpzip)
    extracted = os.path.join(staging, "nuclei-templates-main")
    if not os.path.isdir(extracted):
        subs = [os.path.join(staging, d) for d in os.listdir(staging)]
        extracted = next((d for d in subs if os.path.isdir(d)), staging)
    shutil.rmtree(NUCLEI_TEMPLATES_DIR, ignore_errors=True)
    shutil.move(extracted, NUCLEI_TEMPLATES_DIR)
    shutil.rmtree(staging, ignore_errors=True)
    count = sum(1 for _r, _d, fs in os.walk(NUCLEI_TEMPLATES_DIR)
                for f in fs if f.endswith((".yaml", ".yml")))
    print(f"[*] {count} templates installed in {NUCLEI_TEMPLATES_DIR}")
    print("    Templates (c) ProjectDiscovery, MIT license.")
    print(f"    Run them with:  hakscan -t auto https://target.com")
    print("    Tip: point -t at a subfolder to stay fast/quiet, e.g.")
    print(f"         hakscan -t {os.path.join(NUCLEI_TEMPLATES_DIR, 'http', 'exposures')} https://target.com")
    return 0


# ===========================================================================
#  CLI
# ===========================================================================

HELP = __doc__


def pop_opt(argv: list[str], *names: str):
    for name in names:
        if name in argv:
            i = argv.index(name)
            if i + 1 < len(argv):
                val = argv[i + 1]
                del argv[i:i + 2]
                return val
    return None


def pop_flag(argv: list[str], *names: str) -> bool:
    hit = False
    for name in names:
        while name in argv:
            argv.remove(name)
            hit = True
    return hit


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(HELP)
        return 0
    if argv[0] in ("version", "-version", "--version"):
        print(f"Hakscan v{VERSION}")
        return 0
    if argv[0] in ("update-templates", "update", "ut"):
        return update_templates()

    json_out = pop_opt(argv, "--json", "-o")
    delay = float(pop_opt(argv, "--delay") or 0.3)
    templates = pop_opt(argv, "-t", "--templates")
    passive = pop_flag(argv, "--passive")
    target = pop_opt(argv, "-u", "--url")

    if argv and argv[0] == "file":
        if len(argv) < 2:
            sys.stderr.write("[!] usage: hakscan file <path>\n")
            return 2
        return analyze_file_target(argv[1], json_out)

    if target is None:
        positional = [a for a in argv if not a.startswith("-")]
        if positional:
            target = positional[0]
    if not target:
        sys.stderr.write("[!] No target. See: hakscan -h\n")
        return 2

    if os.path.exists(target):
        return analyze_file_target(target, json_out)

    report = WebScanner(target, delay, templates, active=not passive).run()
    print_report(report)
    if json_out:
        write_json(report, json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
