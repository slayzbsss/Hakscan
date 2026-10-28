# Hakscan

Self-contained web vulnerability scanner and file analyzer. Ships as a single
native binary (Go) - like nuclei - with no runtime dependencies. A Python
implementation (`hakscan.py`) is also included.

> **Authorized use only.** Scan targets you own or have explicit written
> permission to test (e.g. a bug bounty program's scope). Scanning without
> permission is illegal.

## Features

### Web engine
- Missing security headers (HSTS, CSP, X-Frame-Options, COOP/CORP, ...)
- Information-disclosure headers, insecure cookies
- TLS/certificate checks (weak protocol, expiry, validation errors)
- CORS misconfiguration (origin reflection, null origin, wildcard + credentials)
- Risky HTTP methods (TRACE, PUT, DELETE, ...)
- Exposed sensitive files/paths (~100 entries), directory listing
- Git/SVN/HG and `.env` exposure
- Technology fingerprinting and WordPress-specific checks
- Verbose errors / debug pages, mixed content, insecure forms
- Host header injection
- Active parameter tests: reflected XSS, SQL errors, SSTI, LFI, OS command
  injection, CRLF, open redirect
- Custom JSON detection templates (`-t templates/`)

### File engine
- APK / AAB / XAPK / IPA / JAR / WAR / ZIP, binaries, source trees
- Built-in binary `AndroidManifest.xml` parser: debuggable, allowBackup,
  cleartext traffic, exported components, dangerous permissions, embedded keys
- Secret/credential scanner (AWS, GCP, GitHub, Stripe, Slack, JWT, DB URIs, ...)
- Endpoint and hardcoded-IP extraction

## Install

**Download the binary (like nuclei)** from the
[Releases](https://github.com/slayzbsss/Hakscan/releases) page for your OS, then:

```bash
chmod +x hakscan-linux-amd64
./hakscan-linux-amd64 -h
```

Available builds: `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`,
`windows-amd64`. No dependencies required.

**Build from source** (needs Go):

```bash
git clone https://github.com/slayzbsss/Hakscan.git
cd Hakscan
./build.sh            # cross-compiles all platforms into dist/
# or just:  go build -o hakscan .
```

## Usage

```bash
hakscan https://target.com
hakscan -u "https://target.com/page?id=1" --json report.json
hakscan --passive https://target.com        # no active injection tests
hakscan -t my_templates/ https://target.com  # custom templates
hakscan app.apk
hakscan ./source-dir/
```

## Templates

Hakscan runs two template formats:

### Official nuclei templates (YAML)

Download the official community templates once, then run the supported subset:

```bash
hakscan update-templates                 # downloads ~14k templates to ~/.hakscan
hakscan -t auto https://target.com       # run them (or point -t at a subfolder)
hakscan -t ~/.hakscan/nuclei-templates/http/exposures https://target.com
```

Hakscan executes the common HTTP template subset (word/regex/status matchers,
path lists, conditions). Templates using raw requests, DSL matchers, extractors
or multi-step flows are skipped and counted. These templates are the work of
ProjectDiscovery, distributed under the MIT license (see `NOTICE`); Hakscan only
downloads and runs them locally.

### Hakscan templates (JSON), sorted by category

Hakscan's own templates live in a separate repository, sorted by category
(web and APK kept separate):

**https://github.com/slayzbsss/hakscan-templates**

```bash
git clone https://github.com/slayzbsss/hakscan-templates.git
hakscan -t hakscan-templates/web https://target.com   # web HTTP templates
hakscan app.apk -t hakscan-templates/apk              # apk secret signatures
```

Two kinds are supported: `kind: http` (web checks matched against an HTTP
response) and `kind: secret` (extra regex signatures for the file/APK engine).
Add your own by dropping a `.json` file in the matching category folder.

## License

MIT - see [LICENSE](LICENSE).
