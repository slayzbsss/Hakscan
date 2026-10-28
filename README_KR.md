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
  `한국어` •
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

**Hakscan은 간단한 JSON 및 YAML 템플릿을 사용하는 빠르고 독립적인 취약점 스캐너입니다. 의존성이 없는 단일 네이티브 바이너리입니다.**

- 사용자 검사를 만들기 위한 간단한 JSON/YAML 형식.
- 웹 엔진: 헤더, TLS, CORS, 노출, 능동 테스트(XSS, SQLi, SSTI, LFI, 명령어 주입, CRLF, 오픈 리다이렉트).
- 파일 엔진: AndroidManifest.xml 파서 및 시크릿 스캐너(APK/JAR/ZIP, 소스).
- 자체 JSON 템플릿과 커뮤니티 YAML 템플릿 실행.
- 가볍고 크로스 플랫폼이며 CI/CD 친화적.

## 시작하기

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> 소유하거나 서면 허가를 받은 대상에만 사용하세요. 허가 없는 스캔은 불법입니다.

## 사용법

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## 템플릿

템플릿은 카테고리별로 정리된 전용 저장소에 있습니다:
**https://github.com/slayzbsss/hakscan-templates**

## 우리의 미션

전통적인 스캐너는 무겁고 폐쇄적입니다. Hakscan은 작고 열린 엔진을 유지하며 탐지는 읽기 쉬운 템플릿에 담깁니다.

## 라이선스

Hakscan은 MIT 라이선스로 배포됩니다. — [LICENSE.md](LICENSE.md)
