<h1 align="center">
  <img src="assets/logo.svg" alt="Hakscan" width="420"></a>
</h1>

<p align="center">
<a href="https://github.com/slayzbsss/Hakscan/releases"><img src="https://img.shields.io/github/v/release/slayzbsss/Hakscan"></a>
<a href="https://github.com/slayzbsss/Hakscan/blob/main/LICENSE"><img src="https://img.shields.io/github/license/slayzbsss/Hakscan"></a>
<img src="https://img.shields.io/github/go-mod/go-version/slayzbsss/Hakscan">
<a href="https://github.com/slayzbsss/Hakscan/actions/workflows/ci.yml"><img src="https://github.com/slayzbsss/Hakscan/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/slayzbsss/Hakscan/actions/workflows/release.yml"><img src="https://github.com/slayzbsss/Hakscan/actions/workflows/release.yml/badge.svg"></a>
</p>

<p align="center">
  <a href="#get-started">Get Started</a> •
  <a href="#usage">Usage</a> •
  <a href="#templates">Templates</a> •
  <a href="#our-approach">Our Approach</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

Hakscan is a fast, self-contained vulnerability scanner that ships as a single
native binary. It scans web applications for common security issues and analyzes
mobile/binary artifacts (APK, JAR, ZIP) - and it runs your own detection
templates, including the official nuclei YAML templates.

- Single native binary (Go) - no runtime, no dependencies.
- Cross-platform builds for Linux, macOS and Windows (amd64 / arm64).
- Web engine: security headers, TLS, CORS, exposures, and active parameter
  tests (XSS, SQLi, SSTI, LFI, command injection, CRLF, open redirect).
- File engine: built-in `AndroidManifest.xml` parser and secret/credential scanner.
- Runs custom JSON templates and the official nuclei YAML templates.
- CI/CD friendly: JSON output and automated release binaries.

## Table of Contents

- [Get Started](#get-started)
- [Usage](#usage)
  - [Single target scan](#single-target-scan)
  - [File & APK analysis](#file--apk-analysis)
  - [Scanning with templates](#scanning-with-templates)
- [Templates](#templates)
- [Our Approach](#our-approach)
- [Contributing](#contributing)
- [License](#license)

## Get Started

Install with Go:

```console
go install -v github.com/slayzbsss/Hakscan@latest
```

Or download a prebuilt binary from the
[releases](https://github.com/slayzbsss/Hakscan/releases) page
(`linux`, `darwin`, `windows` - `amd64`/`arm64`):

```console
chmod +x hakscan-linux-amd64
./hakscan-linux-amd64 -h
```

Or build from source:

```console
git clone https://github.com/slayzbsss/Hakscan.git
cd Hakscan && go build -o hakscan .
```

> [!IMPORTANT]
> Use Hakscan only against targets you own or are explicitly authorized to test
> (e.g. a bug bounty program's scope). Scanning without permission is illegal.

## Usage

To display all the flags for the tool:

```console
hakscan -h
```

### Single target scan

```console
hakscan https://example.com
hakscan -u "https://example.com/page?id=1" --json report.json
hakscan --passive https://example.com
```

### File & APK analysis

```console
hakscan app.apk
hakscan ./source-dir/
```

### Scanning with templates

```console
hakscan update-templates                 # fetch the official nuclei templates
hakscan -t auto https://example.com       # run them
hakscan -t my_templates/ https://example.com
hakscan app.apk -t my_templates/apk       # custom secret signatures
```

## Templates

Hakscan runs two template formats. Its own templates live in a dedicated,
category-sorted repository:

**https://github.com/slayzbsss/hakscan-templates**

- `kind: http` - web checks matched against an HTTP response.
- `kind: secret` - extra regex signatures for the file/APK engine.

It also runs the official **nuclei** YAML templates (the common HTTP subset:
word/regex/status matchers, path lists, conditions). `hakscan update-templates`
downloads them from ProjectDiscovery's
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT license - see `NOTICE`).

## Our Approach

Traditional scanners are heavy and hard to extend. Hakscan keeps a tiny,
dependency-free core and pushes detection logic into human-readable templates,
so you can encode what you learn about a target and re-run it anywhere - locally
or in CI. It is intentionally simple and honest about its scope: the built-in
engine covers the most common issues, and the template system lets you grow
coverage, including by reusing the nuclei community templates.

## Contributing

Issues, feature requests and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue, see
[SECURITY.md](SECURITY.md).

## License

Hakscan is distributed under the [MIT License](LICENSE).
