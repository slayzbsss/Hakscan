<h1 align="center">
  <img src="assets/logo.svg" alt="Hakscan" width="420"></a>
</h1>

<p align="center">
<strong>English</strong> • <a href="README_FR.md">Français</a>
</p>

<p align="center">
<a href="https://github.com/slayzbsss/Hakscan/releases"><img src="https://img.shields.io/github/v/release/slayzbsss/Hakscan"></a>
<a href="https://github.com/slayzbsss/Hakscan/blob/main/LICENSE.md"><img src="https://img.shields.io/github/license/slayzbsss/Hakscan"></a>
<img src="https://img.shields.io/github/go-mod/go-version/slayzbsss/Hakscan">
<a href="https://github.com/slayzbsss/Hakscan/actions/workflows/ci.yml"><img src="https://github.com/slayzbsss/Hakscan/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/slayzbsss/Hakscan/releases"><img src="https://img.shields.io/github/downloads/slayzbsss/Hakscan/total"></a>
</p>

<p align="center">
  <a href="#get-started">Get Started</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#templates-community-and-contributions">Templates & Community</a> •
  <a href="#our-mission">Our Mission</a> •
  <a href="#contributors">Contributors</a> •
  <a href="#license">License</a>
</p>

---

Hakscan is a fast, self-contained vulnerability scanner that leverages simple
JSON and YAML templates. It empowers you to design custom detection scenarios
that mimic real-world conditions, and it ships as a single native binary with
zero runtime dependencies.

- Single native binary (Go) — no runtime, no dependencies, cross-platform.
- Simple template formats for creating and customizing detection checks.
- Web engine: headers, TLS, CORS, exposures, and active parameter tests
  (XSS, SQLi, SSTI, LFI, command injection, CRLF, open redirect).
- File engine: built-in `AndroidManifest.xml` parser and secret/credential
  scanner for APK/AAB/JAR/ZIP and source trees.
- Runs your own JSON templates and community YAML templates.
- Ultra-light and CI/CD friendly, with JSON output and automated releases.

## Table of Contents

- [Get Started](#get-started)
- [Documentation](#documentation)
  - [Command Line Flags](#command-line-flags)
  - [Single target scan](#single-target-scan)
  - [Scanning multiple targets](#scanning-multiple-targets)
  - [File & APK analysis](#file--apk-analysis)
  - [Scanning with your custom template](#scanning-with-your-custom-template)
- [Templates, Community and Contributions](#templates-community-and-contributions)
- [Our Mission](#our-mission)
- [Contributors](#contributors)
- [License](#license)

## Get Started

Install on your machine with Go:

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
```

Or download a prebuilt binary from the
[releases](https://github.com/slayzbsss/Hakscan/releases) page
(`linux`, `darwin`, `windows` — `amd64`/`arm64`):

```console
chmod +x hakscan
./hakscan -h
```

Or build from source:

```console
git clone https://github.com/slayzbsss/Hakscan.git
cd Hakscan && make build
```

> [!IMPORTANT]
> Use Hakscan only against targets you own or are explicitly authorized to test
> (e.g. a bug bounty program's scope). Scanning without permission is illegal.

## Documentation

### Command Line Flags

To display all the flags for the tool:

```console
hakscan -h
```

<details>
<summary>Expand full help flags</summary>

```console
Hakscan - web vulnerability scanner & file analyzer (native binary)

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
```

</details>

### Single target scan

To perform a quick scan on a web application:

```console
hakscan https://example.com
```

### Scanning multiple targets

Hakscan can handle bulk scanning by providing a list of targets in a file:

```console
hakscan -l urls.txt
```

### File & APK analysis

Analyze a mobile app, archive, binary or an entire source tree for secrets,
embedded endpoints and insecure Android manifest settings:

```console
hakscan app.apk
hakscan ./source-dir/
```

### Scanning with your custom template

Write a `.json` (or community `.yaml`) template with your own rules, then run it:

```console
hakscan -u https://example.com -t /path/to/your-templates/
hakscan update-templates && hakscan -t auto https://example.com
```

## Templates, Community and Contributions

Hakscan templates define how requests are sent and how responses are matched,
giving the scanner easy extensibility. Templates are kept in a dedicated,
category-sorted repository:

**https://github.com/slayzbsss/hakscan-templates**

Two template kinds are supported:

- `kind: http` — web checks matched against an HTTP response.
- `kind: secret` — regex signatures for the file/APK engine.

Hakscan also runs community YAML templates (the common HTTP subset:
`word`/`regex`/`status` matchers, path lists and match conditions); unsupported
constructs are skipped and counted.

### Examples

| Use case | Hakscan template |
| --- | --- |
| Exposed Git repository | `web/exposures/git-config.json` |
| Environment file disclosure | `web/exposures/env-file.json` |
| Directory listing | `web/misconfiguration/directory-listing.json` |
| Exposed phpinfo() | `web/misconfiguration/phpinfo.json` |
| Admin / DB panels | `web/panels/phpmyadmin.json` |
| WordPress user enumeration | `web/cms/wordpress-user-enum.json` |
| Hardcoded secrets in APKs | `apk/secrets/*.json` |

Template contributions, feature requests and bug reports are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Our Mission

Traditional vulnerability scanners are heavy, closed and hard to extend.
Attackers move fast and exploit new issues within days. Hakscan takes a
different approach: a tiny, open, dependency-free engine where detection logic
lives in human-readable templates, so anyone can encode what they learn about a
target and re-run it anywhere — locally or in CI. It is intentionally simple and
honest about its scope, and grows through community templates.

## Contributors

Thanks to everyone who contributes code, templates and bug reports. ❤️
See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.

## License

Hakscan is distributed under the [MIT License](LICENSE.md).
