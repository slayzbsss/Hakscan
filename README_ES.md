<h1 align="center"><img src="assets/logo.svg" alt="Hakscan" width="600"></h1>

<div align="center">

  <a href="README.md">`English`</a> •
  <a href="README_FR.md">`Français`</a> •
  `Español` •
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

---

**Hakscan es un escáner de vulnerabilidades rápido y autónomo basado en plantillas JSON y YAML. Un único binario nativo, sin dependencias.**

- Formato JSON/YAML simple para crear tus detecciones.
- Motor web: cabeceras, TLS, CORS, exposiciones, pruebas activas (XSS, SQLi, SSTI, LFI, inyección de comandos, CRLF, open redirect).
- Motor de archivos: parser de AndroidManifest.xml y escáner de secretos (APK/JAR/ZIP, código).
- Ejecuta tus plantillas JSON y las plantillas YAML de la comunidad.
- Ligero, multiplataforma, apto para CI/CD.

## Empezar

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> Úsalo solo contra objetivos que posees o con autorización escrita. Escanear sin permiso es ilegal.

## Uso

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## Plantillas

Las plantillas están en un repositorio dedicado, ordenadas por categoría:
**https://github.com/slayzbsss/hakscan-templates**

## Nuestra misión

Los escáneres tradicionales son pesados y cerrados. Hakscan mantiene un motor diminuto y abierto donde la detección vive en plantillas legibles.

## Licencia

Hakscan se distribuye bajo licencia MIT. — [LICENSE.md](LICENSE.md)
