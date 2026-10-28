# Debugging Hakscan

## Verbose HTTP

Hakscan prints each phase to stderr (`[*] ...`). Run with a tiny delay to slow
requests down and read them in order:

```console
hakscan https://target.com --delay 500
```

## JSON output

For machine inspection or diffing between runs:

```console
hakscan https://target.com --json out.json
jq '.findings[] | {severity,title,location}' out.json
```

## Templates

- `-t <dir>` loads `.json` (custom) and `.yaml` (community) recursively.
- The run summary reports `run / matched / skipped`; `skipped` means the
  template used an unsupported construct (raw requests, DSL, extractors).
- Point `-t` at a sub-folder to limit scope and speed things up.

## Build with debug info

```console
go build -gcflags="all=-N -l" -o hakscan ./cmd/hakscan
dlv exec ./hakscan -- https://target.com
```
