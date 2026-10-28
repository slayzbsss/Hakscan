![hakscan](assets/hakscan-cover.png)

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
<a href="https://github.com/slayzbsss/Hakscan#documentation"><img src="https://img.shields.io/badge/Documentation-%23000000.svg?style=for-the-badge&logo=book&logoColor=white"></a>
&nbsp;
<a href="https://github.com/slayzbsss/hakscan-templates"><img src="https://img.shields.io/badge/Templates%20Library-%23000000.svg?style=for-the-badge&logo=github&logoColor=white"></a>
&nbsp;
<a href="https://github.com/slayzbsss/Hakscan/discussions"><img src="https://img.shields.io/badge/Discussions-%235865F2.svg?style=for-the-badge&logo=github&logoColor=white"></a>
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
