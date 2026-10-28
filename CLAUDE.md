# Repo context

Hakscan is a single-binary web/file vulnerability scanner written in Go.

## Build & test

```console
make build        # -> ./hakscan
make vet
make test
go run ./cmd/hakscan https://example.com
```

## Layout

- `cmd/hakscan/main.go` — entrypoint and all engines (CLI, HTTP, web checks,
  file/APK engine, AXML parser, secret scanner, template runner, reporting).
- `.goreleaser.yml` — release build (triggered by `v*` tags via GitHub Actions).
- Templates live in a separate repo: `slayzbsss/hakscan-templates`.

## Conventions

- Keep the core dependency-free (stdlib + `gopkg.in/yaml.v3`).
- Findings use `Finding{title, severity, detail, location, evidence}`.
- Severities: info | low | medium | high | critical.
- Security tool: only add features intended for authorized, lawful testing.
