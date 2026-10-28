<h1 align="center"><img src="assets/logo.svg" alt="Hakscan" width="420"></h1>
<p align="center"><a href="README.md">English</a> • <a href="README_FR.md">Français</a> • <a href="README_ES.md">Español</a> • <strong>Português</strong></p>

---

Hakscan é um scanner de vulnerabilidades rápido e autônomo baseado em templates
JSON e YAML. Distribuído como um único binário nativo, sem dependências.

## Começar

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
yay -S hakscan-bin
```

> [!IMPORTANT]
> Use apenas contra alvos que você possui ou está explicitamente autorizado a
> testar. Escanear sem permissão é ilegal.

## Uso

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

Templates: https://github.com/slayzbsss/hakscan-templates

## Licença

[MIT](LICENSE.md).
