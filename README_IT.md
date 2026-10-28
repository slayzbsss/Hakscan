![hakscan](assets/banner.png)

<div align="center">

  <a href="README.md">`English`</a> •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_ES.md">`Español`</a> •
  <a href="README_PT-BR.md">`Português`</a> •
  <a href="README_DE.md">`Deutsch`</a> •
  `Italiano` •
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

**Hakscan è uno scanner di vulnerabilità veloce e autonomo basato su semplici template JSON e YAML. Un unico binario nativo, senza dipendenze.**

- Formato JSON/YAML semplice per creare i tuoi controlli.
- Motore web: header, TLS, CORS, esposizioni, test attivi (XSS, SQLi, SSTI, LFI, command injection, CRLF, open redirect).
- Motore file: parser AndroidManifest.xml e scanner di segreti (APK/JAR/ZIP, codice).
- Esegue i tuoi template JSON e i template YAML della community.
- Leggero, multipiattaforma, pronto per CI/CD.

## Per iniziare

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> Usa solo su bersagli che possiedi o per cui hai autorizzazione scritta. Scansionare senza permesso è illegale.

## Utilizzo

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## Template

I template sono in un repository dedicato, ordinati per categoria:
**https://github.com/slayzbsss/hakscan-templates**

## La nostra missione

Gli scanner tradizionali sono pesanti e chiusi. Hakscan mantiene un motore minuscolo e aperto dove il rilevamento vive in template leggibili.

## Licenza

Hakscan è distribuito sotto licenza MIT. — [LICENSE.md](LICENSE.md)
