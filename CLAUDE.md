# Repo context

Hakscan is a single-binary web/file vulnerability scanner written in Go.

## Build & test

```console
make build        # -> ./hakscan
make vet
make test
go run ./cmd/hakscan https://example.com
```

## Layout (nuclei-style)

- `cmd/hakscan/main.go` — thin CLI: flag parsing, banner, startup info, dispatch.
- `pkg/output/` — `Finding`, `Report`, severities, console + JSON output, `Mask`.
- `pkg/httpx/` — HTTP client (`Resp`, `DoHTTP`), `Version`, `UserAgent`.
- `pkg/web/` — web engine: `WebScanner`, header/TLS/CORS checks, injections,
  and the HTTP template runner.
- `pkg/file/` — file engine: APK/ZIP archives, AndroidManifest (AXML) parser,
  DEX string tables, ELF sections, secret/credential scanner.
- `pkg/templates/` — template matching primitives (`NucleiMatch`, word/regex).
- `pkg/update/` — version check (GitHub) + `update-templates`.
- `lib/hakscan.go` — library SDK: `ScanWeb`, `ScanFile` returning `*output.Report`.
- `.goreleaser.yml` — release build (triggered by `v*` tags via GitHub Actions).
- Templates live in a separate repo: `slayzbsss/hakscan-templates`.

## Conventions

- Keep the core dependency-free (stdlib + `gopkg.in/yaml.v3`).
- Findings use `Finding{title, severity, detail, location, evidence}`.
- Severities: info | low | medium | high | critical.
- Security tool: only add features intended for authorized, lawful testing.
