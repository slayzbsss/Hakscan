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
  <a href="README_TR.md">`Türkçe`</a> •
  <a href="README_ID.md">`Indonesia`</a> •
  <a href="README_FA.md">`فارسی`</a> •
  `العربية` •
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

**Hakscan ماسح ثغرات سريع ومستقل يعتمد على قوالب JSON وYAML بسيطة. ملف تنفيذي أصلي واحد، بلا تبعيات.**

- صيغة JSON/YAML بسيطة لإنشاء اكتشافاتك.
- محرك ويب: الترويسات، TLS، CORS، التسريبات، واختبارات نشطة (XSS، SQLi، SSTI، LFI، حقن الأوامر، CRLF، إعادة التوجيه المفتوحة).
- محرك ملفات: محلّل AndroidManifest.xml وماسح الأسرار (APK/JAR/ZIP، الشيفرة).
- تشغيل قوالب JSON الخاصة بك وقوالب YAML من المجتمع.
- خفيف، متعدد المنصات، ملائم لـ CI/CD.

## البداية

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> استخدمه فقط على أهداف تملكها أو لديك إذن كتابي بها. الفحص بدون إذن غير قانوني.

## الاستخدام

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## القوالب

توجد القوالب في مستودع مخصص، مرتبة حسب الفئة:
**https://github.com/slayzbsss/hakscan-templates**

## مهمتنا

الماسحات التقليدية ثقيلة ومغلقة. يحافظ Hakscan على محرك صغير ومفتوح حيث يُكتب الاكتشاف في قوالب قابلة للقراءة.

## الرخصة

يُوزَّع Hakscan بموجب رخصة MIT. — [LICENSE.md](LICENSE.md)
