![hakscan](assets/banner.png)

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

<a href="https://github.com/slayzbsss/Hakscan#documentation"><img src="https://img.shields.io/badge/Documentation-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBjbGFzcz0ibHVjaWRlIGx1Y2lkZS1ib29rLW9wZW4iPjxwYXRoIGQ9Ik0xMiA3djE0Ii8+PHBhdGggZD0iTTMgMThhMSAxIDAgMCAxLTEtMVY0YTEgMSAwIDAgMSAxLTFoNWE0IDQgMCAwIDEgNCA0IDQgNCAwIDAgMSA0LTRoNWExIDEgMCAwIDEgMSAxdjEzYTEgMSAwIDAgMS0xIDFoLTZhMyAzIDAgMCAwLTMgMyAzIDMgMCAwIDAtMy0zeiIvPjwvc3ZnPg==&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://github.com/slayzbsss/hakscan-templates"><img src="https://img.shields.io/badge/Templates Library-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMS41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGNsYXNzPSJsdWNpZGUgbHVjaWRlLXNoaWVsZCI+PHBhdGggZD0iTTIwIDEzYzAgNS0zLjUgNy41LTcuNjYgOC45NWExIDEgMCAwIDEtLjY3LS4wMUM3LjUgMjAuNSA0IDE4IDQgMTNWNmExIDEgMCAwIDEgMS0xYzIgMCA0LjUtMS4yIDYuMjQtMi43MmExLjE3IDEuMTcgMCAwIDEgMS41MiAwQzE0LjUxIDMuODEgMTcgNSAxOSA1YTEgMSAwIDAgMSAxIDF6Ii8+PC9zdmc+&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://discord.com/users/1246872545375027293"><img src="https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white"></a>

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
