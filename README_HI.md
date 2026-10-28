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
  <a href="README_AR.md">`العربية`</a> •
  `हिन्दी`

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

**Hakscan एक तेज़, स्वतंत्र भेद्यता स्कैनर है जो सरल JSON और YAML टेम्पलेट्स पर आधारित है। बिना किसी निर्भरता के एकल नेटिव बाइनरी।**

- अपनी जाँच बनाने के लिए सरल JSON/YAML प्रारूप।
- वेब इंजन: हेडर, TLS, CORS, एक्सपोज़र, और सक्रिय परीक्षण (XSS, SQLi, SSTI, LFI, कमांड इंजेक्शन, CRLF, ओपन रीडायरेक्ट)।
- फ़ाइल इंजन: AndroidManifest.xml पार्सर और सीक्रेट स्कैनर (APK/JAR/ZIP, स्रोत)।
- अपने JSON टेम्पलेट और समुदाय के YAML टेम्पलेट चलाएँ।
- हल्का, क्रॉस-प्लेटफ़ॉर्म, CI/CD के अनुकूल।

## शुरू करें

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> केवल उन लक्ष्यों पर उपयोग करें जिनके आप स्वामी हैं या जिनके लिए आपके पास लिखित अनुमति है। बिना अनुमति स्कैन करना अवैध है।

## उपयोग

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## टेम्पलेट

टेम्पलेट एक समर्पित रिपॉज़िटरी में, श्रेणी अनुसार हैं:
**https://github.com/slayzbsss/hakscan-templates**

## हमारा मिशन

पारंपरिक स्कैनर भारी और बंद होते हैं। Hakscan एक छोटा, खुला इंजन रखता है जहाँ जाँच पठनीय टेम्पलेट्स में रहती है।

## लाइसेंस

Hakscan MIT लाइसेंस के अंतर्गत वितरित है। — [LICENSE.md](LICENSE.md)
