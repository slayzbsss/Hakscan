# Fuzzing

The binary `AndroidManifest.xml` (AXML) parser is the main untrusted-input
surface, so it has a native Go fuzz target.

## Run

```console
go test -run xxx -fuzz FuzzParseAXML -fuzztime 30s ./cmd/hakscan
```

The target lives in `cmd/hakscan/main_test.go` (`FuzzParseAXML`). It feeds random
bytes to `parseAXML` and asserts it never panics (the parser does bounds checks
and recovers internally). Crash inputs are written to `testdata/fuzz/` and can
be replayed with `go test`.

## Unit tests

```console
go test ./...
```
