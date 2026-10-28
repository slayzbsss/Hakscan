# Design

Hakscan is a single-binary scanner with two engines sharing one CLI and one
reporting model.

## Overview

```
cmd/hakscan/main.go
 ├── CLI dispatch        (web target | file/dir | update-templates)
 ├── HTTP client         (follow / no-redirect, bounded body)
 ├── Web engine          (passive checks + active parameter tests)
 ├── File engine         (archive/APK walk, AXML parser, secret scanner)
 ├── Template runner     (JSON "http"/"secret" + YAML subset)
 └── Report              (sorted findings, text + JSON output)
```

## Web engine

Runs an ordered set of checks against a target: response headers, cookies, TLS,
CORS, allowed methods, technology fingerprint, verbose errors, mixed content,
insecure forms, host-header injection, exposed paths and VCS/.env leaks. When
the target has query parameters and active mode is on, it runs non-destructive
parameter probes (reflected XSS, SQL errors, SSTI, path traversal, command
injection, CRLF, open redirect).

## File engine

Opens archives (APK/AAB/JAR/ZIP) and directories, scans every member for
secrets with a regex signature set, extracts referenced endpoints and IPs, and
parses the binary `AndroidManifest.xml` (string pool + start-element chunks) to
flag `debuggable`, `allowBackup`, cleartext traffic, exported components,
dangerous permissions and embedded API keys.

## Templates

Two formats are supported:

- **JSON** - `kind: http` (matched against a response) and `kind: secret`
  (regex signatures for the file engine).
- **YAML** - the common HTTP subset: `word`/`regex`/`status` matchers, path
  lists and match conditions. Unsupported constructs are skipped and counted.

## Reporting

Every check appends a `Finding{title, severity, detail, location, evidence}` to
a `Report`, which is printed sorted by severity and optionally written as JSON.
