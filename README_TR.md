![hakscan](assets/banner.png)

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
  `Türkçe` •
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

**Hakscan, basit JSON ve YAML şablonları kullanan hızlı ve bağımsız bir zafiyet tarayıcısıdır. Bağımlılığı olmayan tek bir yerel ikili dosya.**

- Kendi tespitlerinizi oluşturmak için basit JSON/YAML biçimi.
- Web motoru: başlıklar, TLS, CORS, ifşalar, aktif testler (XSS, SQLi, SSTI, LFI, komut enjeksiyonu, CRLF, açık yönlendirme).
- Dosya motoru: AndroidManifest.xml ayrıştırıcı ve sır tarayıcı (APK/JAR/ZIP, kaynak).
- Kendi JSON şablonlarınızı ve topluluk YAML şablonlarını çalıştırır.
- Hafif, çok platformlu, CI/CD uyumlu.

## Başlarken

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> Yalnızca sahip olduğunuz veya yazılı izniniz olan hedeflerde kullanın. İzinsiz tarama yasa dışıdır.

## Kullanım

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## Şablonlar

Şablonlar, kategoriye göre ayrılmış özel bir depodadır:
**https://github.com/slayzbsss/hakscan-templates**

## Misyonumuz

Geleneksel tarayıcılar ağır ve kapalıdır. Hakscan, tespitin okunabilir şablonlarda yaşadığı küçük ve açık bir motoru korur.

## Lisans

Hakscan MIT lisansı altında dağıtılır. — [LICENSE.md](LICENSE.md)
