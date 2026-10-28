<h1 align="center"><img src="assets/logo.svg" alt="Hakscan" width="600"></h1>

<div align="center">

  <a href="README.md">`English`</a> •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_ES.md">`Español`</a> •
  <a href="README_PT-BR.md">`Português`</a> •
  <a href="README_DE.md">`Deutsch`</a> •
  <a href="README_IT.md">`Italiano`</a> •
  <a href="README_CN.md">`中文`</a> •
  <a href="README_JP.md">`日本語`</a> •
  <a href="README_KR.md">`한국어`</a> •
  <a href="README_RU.md">`Русский`</a> •
  <a href="README_TR.md">`Türkçe`</a> •
  `Indonesia` •
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

**Hakscan adalah pemindai kerentanan yang cepat dan mandiri berbasis template JSON dan YAML sederhana. Satu biner native, tanpa dependensi.**

- Format JSON/YAML sederhana untuk membuat deteksi Anda.
- Mesin web: header, TLS, CORS, ekspos, uji aktif (XSS, SQLi, SSTI, LFI, command injection, CRLF, open redirect).
- Mesin file: parser AndroidManifest.xml dan pemindai rahasia (APK/JAR/ZIP, kode).
- Menjalankan template JSON Anda dan template YAML komunitas.
- Ringan, lintas platform, siap CI/CD.

## Mulai

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> Gunakan hanya pada target yang Anda miliki atau yang Anda punya izin tertulis. Memindai tanpa izin adalah ilegal.

## Penggunaan

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## Template

Template berada di repositori khusus, diurutkan per kategori:
**https://github.com/slayzbsss/hakscan-templates**

## Misi Kami

Pemindai tradisional berat dan tertutup. Hakscan mempertahankan mesin mungil dan terbuka di mana deteksi ditulis dalam template yang mudah dibaca.

## Lisensi

Hakscan didistribusikan di bawah Lisensi MIT. — [LICENSE.md](LICENSE.md)
