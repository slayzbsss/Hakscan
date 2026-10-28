<h1 align="center"><img src="assets/logo.svg" alt="Hakscan" width="600"></h1>

<div align="center">

  `English` •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_ES.md">`Español`</a> •
  <a href="README_PT-BR.md">`Português`</a> •
  <a href="README_DE.md">`Deutsch`</a> •
  <a href="README_IT.md">`Italiano`</a> •
  <a href="README_CN.md">`中文`</a> •
  <a href="README_JP.md">`日本語`</a> •
  <a href="README_KR.md">`한국어`</a> •
  <a href="README_RU.md">`Русский`</a> •
  <a href="README_TR.md">`Türkçe`</a> •
  <a href="README_ID.md">`Indonesia`</a> •
  <a href="README_FA.md">`فارسی`</a> •
  <a href="README_AR.md">`العربية`</a> •
  <a href="README_HI.md">`हिन्दी`</a>

</div>

<p align="center">
<a href="https://github.com/slayzbsss/Hakscan#documentation"><img src="https://img.shields.io/badge/Documentation-%23000000.svg?style=for-the-badge&logo=book&logoColor=white"></a>
&nbsp;
<a href="https://github.com/slayzbsss/hakscan-templates"><img src="https://img.shields.io/badge/Templates%20Library-%23000000.svg?style=for-the-badge&logo=github&logoColor=white"></a>
&nbsp;
<a href="https://github.com/slayzbsss/Hakscan/discussions"><img src="https://img.shields.io/badge/Discussions-%235865F2.svg?style=for-the-badge&logo=github&logoColor=white"></a>
<hr>
</p>

<br>

**Hakscan is a fast, self-contained vulnerability scanner that leverages simple JSON and YAML templates. It empowers you to design custom detection scenarios that mimic real-world conditions, and ships as a single native binary.**

- Simple JSON/YAML format for creating and customizing detection templates.
- Web engine: headers, TLS, CORS, exposures, and active parameter tests (XSS, SQLi, SSTI, LFI, command injection, CRLF, open redirect).
- File engine: built-in AndroidManifest.xml parser and secret/credential scanner for APK/AAB/JAR/ZIP and source trees.
- Runs your own JSON templates and community YAML templates.
- Ultra-light, cross-platform, and CI/CD friendly with JSON output.
- Installable via package managers (AUR/yay, .deb, .rpm, .apk, Go).

<br>

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

<br>

## Get Started

### 1. Hakscan CLI

Install Hakscan on your machine:

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

Or download a prebuilt binary from the [releases](https://github.com/slayzbsss/Hakscan/releases) page, or build from source with `make build`.

> [!IMPORTANT]
> Use Hakscan only against targets you own or are explicitly authorized to test (e.g. a bug bounty program's scope). Scanning without permission is illegal.

<br>

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

```console
hakscan https://example.com
```

### Scanning multiple targets

```console
hakscan -l urls.txt
```

### File & APK analysis

```console
hakscan app.apk
hakscan ./source-dir/
```

### Scanning with your custom template

```console
hakscan -u https://example.com -t /path/to/your-templates/
hakscan update-templates && hakscan -t auto https://example.com
```

<br>

## Templates, Community and Contributions

Hakscan templates define how requests are sent and how responses are matched. They live in a dedicated, category-sorted repository:

**https://github.com/slayzbsss/hakscan-templates**

Two kinds are supported: `kind: http` (web checks) and `kind: secret` (file/APK signatures). Community YAML templates (HTTP subset) are supported too.

#### Examples

| Use case | Hakscan template |
| :--- | :--- |
| Exposed Git repository | `web/exposures/git-config.json` |
| Environment file disclosure | `web/exposures/env-file.json` |
| Directory listing | `web/misconfiguration/directory-listing.json` |
| Exposed phpinfo() | `web/misconfiguration/phpinfo.json` |
| Admin / DB panels | `web/panels/phpmyadmin.json` |
| WordPress user enumeration | `web/cms/wordpress-user-enum.json` |
| Hardcoded secrets in APKs | `apk/secrets/*.json` |

<br>

## Our Mission

Traditional vulnerability scanners are heavy, closed and hard to extend. Hakscan takes a different approach: a tiny, open, dependency-free engine where detection logic lives in human-readable templates, so anyone can encode what they learn about a target and re-run it anywhere — locally or in CI.

<br>

## Contributors

Thanks to everyone who contributes code, templates and bug reports. ❤️ See the [contributors graph](https://github.com/slayzbsss/Hakscan/graphs/contributors).

<p align="left">
<a href="https://github.com/slayzbsss"><img src="https://github.com/slayzbsss.png" width="50" height="50" alt="slayzbsss" style="border-radius:50%"></a>
</p>

<br>
<br>

<div align="center">
  <sub><b>hakscan</b> is distributed under the <a href="https://github.com/slayzbsss/Hakscan/blob/main/LICENSE.md">MIT License</a></sub>
</div>
