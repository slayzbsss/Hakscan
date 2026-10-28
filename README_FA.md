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
  <a href="README_ID.md">`Indonesia`</a> •
  `فارسی` •
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

**Hakscan یک اسکنر آسیب‌پذیری سریع و مستقل مبتنی بر قالب‌های ساده JSON و YAML است. یک باینری بومی واحد، بدون وابستگی.**

- قالب ساده JSON/YAML برای ساخت تشخیص‌های دلخواه.
- موتور وب: هدرها، TLS، CORS، افشاها و آزمون‌های فعال (XSS، SQLi، SSTI، LFI، تزریق فرمان، CRLF، ریدایرکت باز).
- موتور فایل: تجزیه‌گر AndroidManifest.xml و اسکنر اسرار (APK/JAR/ZIP، کد).
- اجرای قالب‌های JSON شما و قالب‌های YAML جامعه.
- سبک، چندسکویی و مناسب CI/CD.

## شروع

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> فقط روی اهدافی که مالک آن‌ها هستید یا اجازه کتبی دارید استفاده کنید. اسکن بدون اجازه غیرقانونی است.

## استفاده

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## قالب‌ها

قالب‌ها در یک مخزن اختصاصی و دسته‌بندی‌شده قرار دارند:
**https://github.com/slayzbsss/hakscan-templates**

## مأموریت ما

اسکنرهای سنتی سنگین و بسته‌اند. Hakscan یک موتور کوچک و باز را حفظ می‌کند که تشخیص در قالب‌های خوانا نوشته می‌شود.

## مجوز

Hakscan تحت مجوز MIT منتشر می‌شود. — [LICENSE.md](LICENSE.md)
