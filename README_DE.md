![hakscan](assets/banner.png)

<div align="center">

  <a href="README.md">`English`</a> •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_ES.md">`Español`</a> •
  <a href="README_PT-BR.md">`Português`</a> •
  `Deutsch` •
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

**Hakscan ist ein schneller, eigenständiger Schwachstellen-Scanner auf Basis einfacher JSON- und YAML-Templates. Eine einzige native Binärdatei, ohne Abhängigkeiten.**

- Einfaches JSON/YAML-Format für eigene Prüfungen.
- Web-Engine: Header, TLS, CORS, Expositionen, aktive Tests (XSS, SQLi, SSTI, LFI, Command Injection, CRLF, Open Redirect).
- Datei-Engine: AndroidManifest.xml-Parser und Secret-Scanner (APK/JAR/ZIP, Quellcode).
- Führt eigene JSON-Templates und Community-YAML-Templates aus.
- Leicht, plattformübergreifend, CI/CD-tauglich.

## Loslegen

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> Nur gegen Ziele verwenden, die du besitzt oder für die du eine schriftliche Erlaubnis hast. Scannen ohne Erlaubnis ist illegal.

## Verwendung

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## Templates

Die Templates liegen in einem eigenen Repository, nach Kategorie sortiert:
**https://github.com/slayzbsss/hakscan-templates**

## Unsere Mission

Klassische Scanner sind schwer und geschlossen. Hakscan hält eine winzige, offene Engine, in der die Erkennung in lesbaren Templates lebt.

## Lizenz

Hakscan wird unter der MIT-Lizenz vertrieben. — [LICENSE.md](LICENSE.md)
