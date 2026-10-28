<h1 align="center"><img src="assets/logo.svg" alt="Hakscan" width="420"></h1>
<p align="center"><a href="README.md">English</a> • <a href="README_FR.md">Français</a> • <strong>Español</strong> • <a href="README_PT-BR.md">Português</a></p>

---

Hakscan es un escáner de vulnerabilidades rápido y autónomo basado en plantillas
JSON y YAML. Se distribuye como un único binario nativo, sin dependencias.

## Empezar

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
yay -S hakscan-bin
```

> [!IMPORTANT]
> Úsalo solo contra objetivos que posees o para los que tienes autorización
> explícita por escrito. Escanear sin permiso es ilegal.

## Uso

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

Plantillas: https://github.com/slayzbsss/hakscan-templates

## Licencia

[MIT](LICENSE.md).
