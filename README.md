![hakscan](assets/banner.png)

<div align="center">

  `English` •
  <a href="README_CN.md">`中文`</a> •
  <a href="README_KR.md">`Korean`</a> •
  <a href="README_ID.md">`Indonesia`</a> •
  <a href="README_ES.md">`Spanish`</a> •
  <a href="README_JP.md">`日本語`</a> •
  <a href="README_PT-BR.md">`Portuguese`</a> •
  <a href="README_TR.md">`Türkçe`</a> •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_DE.md">`Deutsch`</a> •
  <a href="README_IT.md">`Italiano`</a> •
  <a href="README_RU.md">`Русский`</a> •
  <a href="README_FA.md">`فارسی`</a> •
  <a href="README_AR.md">`العربية`</a> •
  <a href="README_HI.md">`हिन्दी`</a>

</div>

<p align="center">

<a href="https://github.com/slayzbsss/Hakscan#documentation"><img src="https://img.shields.io/badge/Documentation-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBjbGFzcz0ibHVjaWRlIGx1Y2lkZS1ib29rLW9wZW4iPjxwYXRoIGQ9Ik0xMiA3djE0Ii8+PHBhdGggZD0iTTMgMThhMSAxIDAgMCAxLTEtMVY0YTEgMSAwIDAgMSAxLTFoNWE0IDQgMCAwIDEgNCA0IDQgNCAwIDAgMSA0LTRoNWExIDEgMCAwIDEgMSAxdjEzYTEgMSAwIDAgMS0xIDFoLTZhMyAzIDAgMCAwLTMgMyAzIDMgMCAwIDAtMy0zeiIvPjwvc3ZnPg==&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://github.com/slayzbsss/hakscan-templates"><img src="https://img.shields.io/badge/Templates Library-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMS41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGNsYXNzPSJsdWNpZGUgbHVjaWRlLXNoaWVsZCI+PHBhdGggZD0iTTIwIDEzYzAgNS0zLjUgNy41LTcuNjYgOC45NWExIDEgMCAwIDEtLjY3LS4wMUM3LjUgMjAuNSA0IDE4IDQgMTNWNmExIDEgMCAwIDEgMS0xYzIgMCA0LjUtMS4yIDYuMjQtMi43MmExLjE3IDEuMTcgMCAwIDEgMS41MiAwQzE0LjUxIDMuODEgMTcgNSAxOSA1YTEgMSAwIDAgMSAxIDF6Ii8+PC9zdmc+&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://discord.com/users/1246872545375027293"><img src="https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white"></a>

<hr>

</p>

<br>

**Hakscan is a fast, self-contained vulnerability scanner that leverages simple JSON and YAML templates. It empowers you to design custom detection scenarios that mimic real-world conditions, and ships as a single native binary.**

- Simple JSON/YAML format for creating and customizing detection templates.
- Web engine: headers, TLS, CORS, exposures, and active parameter tests (XSS, SQLi, SSTI, LFI, command injection, CRLF, open redirect).
- File engine: AndroidManifest parser, DEX bytecode string extraction, ELF native-library analysis, APK `assets/` scanning, and a secret/credential scanner for APK/AAB/JAR/ZIP and source trees.
- Runs your own JSON templates and the community YAML templates.
- Ultra-fast, dependency-free, and CI/CD friendly with JSON output.
- Cross-platform single binary — installable via Go and package managers (AUR, .deb, .rpm, .apk).

<br>
<br>

## Table of Contents

- [**`Get Started`**](#get-started)
  - [_`1. Hakscan CLI`_](#1-hakscan-cli)
- [**`Documentation`**](#documentation)
  - [_`Installation`_](#installation)
  - [_`Command Line Flags`_](#command-line-flags)
  - [_`Single target scan`_](#single-target-scan)
  - [_`Scanning multiple targets`_](#scanning-multiple-targets)
  - [_`File & APK analysis`_](#file--apk-analysis)
  - [_`Scanning with your custom template`_](#scanning-with-your-custom-template)
- [**`Hakscan Templates, Community and Contributions`**](#hakscan-templates-community-and-contributions)
- [**`Our Mission`**](#our-mission)
- [**`Contributors`**](#contributors-heart) ❤
- [**`License`**](#license)

<br>
<br>

## Get Started

### **1. Hakscan CLI**

_Install Hakscan on your machine and start scanning in seconds. Hakscan is a single self-contained binary with no runtime dependencies — point it at a target and go._

> [!IMPORTANT]
> |**This project is in active development.** Expect breaking changes with releases; review the release changelog before updating.|
> |:--------------------------------|
> | Use Hakscan **only** against targets you own or are explicitly authorized to test (e.g. a bug bounty program's scope). Scanning without permission is illegal. |

<br>
<br>

## Documentation

### Installation

Install the latest release in one command (Linux & macOS, no Go required):

```sh
curl -fsSL https://raw.githubusercontent.com/slayzbsss/Hakscan/main/install.sh | bash
```

This downloads the right prebuilt binary for your OS/architecture and installs it to a directory on your `PATH`.

<details>
  <summary>Other installation methods</summary>

**Windows** — download the `.zip` from the [**`releases`**](https://github.com/slayzbsss/Hakscan/releases/latest) page and add the extracted `hakscan.exe` to your `PATH`.

**With Go** (requires go >= 1.27):

```sh
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
```

> `go install` places the binary in `$(go env GOPATH)/bin` (usually `~/go/bin`). If
> `hakscan: command not found`, that directory isn't on your `PATH`:
> `export PATH="$PATH:$(go env GOPATH)/bin"`   # add to ~/.bashrc or ~/.zshrc to persist

**Package managers** — `.deb`, `.rpm`, `.apk` and Arch (`.pkg.tar.zst`) packages are attached to every [**`release`**](https://github.com/slayzbsss/Hakscan/releases/latest). On Debian/Ubuntu, for example:

```sh
sudo dpkg -i hakscan_*_linux_amd64.deb   # installs to /usr/bin/hakscan
```

</details>

### Command Line Flags

To display all the flags for the tool:

```sh
hakscan -h
```

<details>
  <summary>Expand full help flags</summary>

```yaml
Hakscan is a fast, template-based web & file vulnerability scanner,
shipped as a single dependency-free native binary.

Usage:
  hakscan [flags] <target>

Flags:
TARGET:
   -u, --url string             target URL/host to scan
   -l, --list string            path to a file with targets to scan (one per line)
   <file|dir>                   analyze an APK/AAB/JAR/ZIP, DEX or ELF, or a directory

TEMPLATES:
   -t, --templates string       run JSON/YAML templates from a directory ("auto" = community set)

SCAN:
       --passive                passive only - no active injection probes (headers, TLS, exposures)
       --delay int              delay between HTTP requests in milliseconds (default 300)

OUTPUT:
   -o, --json string            write a JSON report to the given file

UPDATE:
       update-templates         download / update the community template set

DEBUG:
       version                  show the hakscan version
   -duc, --disable-update-check skip the GitHub version check at startup
   -h, --help                   show this help message

EXAMPLES:
   # Web scan on a single host
   $ hakscan https://example.com

   # Custom templates, or the community set
   $ hakscan -t ./templates/ https://example.com
   $ hakscan -t auto https://example.com

   # Many targets, with a JSON report
   $ hakscan -l targets.txt -o report.json

   # Analyze a mobile app or a native binary
   $ hakscan app.apk
   $ hakscan ./libnative.so

Documentation: https://github.com/slayzbsss/Hakscan
Authorized targets only. Scanning without permission is illegal.
```

</details>

### Single target scan

To perform a quick scan on a web application:

```sh
hakscan https://example.com
```

### Scanning multiple targets

Hakscan can handle bulk scanning by providing a list of targets. You can use a file containing multiple URLs.

```sh
hakscan -l urls.txt
```

### File & APK analysis

Point Hakscan at a file or a directory to run the file engine (AndroidManifest parser + secret/credential scanner) instead of a web scan.

```sh
hakscan app.apk
hakscan ./source-dir/
```

### Scanning with your custom template

To write and use your own template, create a `.json` (or `.yaml`) file with specific rules, then use it as follows.

```sh
hakscan -u https://example.com -t /path/to/your-templates/
hakscan update-templates && hakscan -t auto https://example.com
```

<br>
<br>

## Hakscan Templates, Community and Contributions 💎

[**Hakscan templates**](https://github.com/slayzbsss/hakscan-templates) are based on the concept of template files that define how requests will be sent and how responses are matched. This allows easy extensibility: the templates are written in a simple, human-readable format to quickly define the detection process.

Two kinds are supported: `kind: http` (web checks) and `kind: secret` (file/APK signatures). The community YAML templates (HTTP subset) are supported too, so you can run thousands of existing checks out of the box with `hakscan update-templates`.

#### Examples

| Use case | Hakscan template |
| :--- | :--- |
| Detect exposed Git repository | **`web/exposures/git-config.json`** |
| Environment file disclosure | **`web/exposures/env-file.json`** |
| Directory listing | **`web/misconfiguration/directory-listing.json`** |
| Exposed phpinfo() | **`web/misconfiguration/phpinfo.json`** |
| Admin / DB panels | **`web/panels/phpmyadmin.json`** |
| WordPress user enumeration | **`web/cms/wordpress-user-enum.json`** |
| Hardcoded secrets in APKs | **`apk/secrets/*.json`** |

<br>
<br>

## Our Mission

Traditional vulnerability scanners are heavy, closed-source and hard to extend. Hakscan takes a different approach: a tiny, open, dependency-free engine where the detection logic lives in human-readable templates, so anyone can encode what they learn about a target and re-run it anywhere — locally or in CI.

You can participate by contributing to our code or the [**`templates library`**](https://github.com/slayzbsss/hakscan-templates).

<br>
<br>

## Contributors :heart:

Thanks to all the amazing contributors for sending PRs and keeping this project updated. :heart:

<p align="left">
<a href="https://github.com/slayzbsss"><img src="https://github.com/slayzbsss.png" width="50" height="50" alt="slayzbsss" style="max-width: 100%;"></a>
</p>

<br>
<br>
<br>

<div align="center">

  <sub>**`hakscan`** is distributed under [**MIT License**](https://github.com/slayzbsss/Hakscan/blob/main/LICENSE.md)</sub>

</div>
