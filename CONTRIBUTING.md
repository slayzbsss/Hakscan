# Contributing to Hakscan

Thanks for your interest in improving Hakscan!

## Ways to contribute

- **Bug reports** - open an issue with steps to reproduce.
- **Feature requests** - open an issue describing the use case.
- **Pull requests** - fork, create a branch, and submit a PR.
- **Templates** - contribute detection templates to
  [hakscan-templates](https://github.com/slayzbsss/hakscan-templates).

## Development

```console
git clone https://github.com/slayzbsss/Hakscan.git
cd Hakscan
go build -o hakscan .
go vet ./...
```

Please keep the core dependency-free (standard library + `gopkg.in/yaml.v3`).

## Responsible use

Hakscan is a security testing tool. Only contribute features and tests intended
for authorized testing. Do not add payloads designed purely for destruction,
denial of service, or evading detection for malicious purposes.
