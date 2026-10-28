<h1 align="center"><img src="assets/logo.svg" alt="Hakscan" width="600"></h1>

<div align="center">

  <a href="README.md">`English`</a> •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_ES.md">`Español`</a> •
  <a href="README_PT-BR.md">`Português`</a> •
  <a href="README_DE.md">`Deutsch`</a> •
  <a href="README_IT.md">`Italiano`</a> •
  `中文` •
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

**Hakscan 是一个快速、独立的漏洞扫描器，基于简单的 JSON 和 YAML 模板。单个原生二进制文件，无任何依赖。**

- 简单的 JSON/YAML 格式，用于创建自定义检测。
- Web 引擎：响应头、TLS、CORS、信息暴露，以及主动测试（XSS、SQLi、SSTI、LFI、命令注入、CRLF、开放重定向）。
- 文件引擎：内置 AndroidManifest.xml 解析器和密钥扫描器（APK/JAR/ZIP、源码）。
- 运行你自己的 JSON 模板以及社区 YAML 模板。
- 轻量、跨平台、适配 CI/CD。

## 开始使用

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> 仅可用于你拥有或已获得书面授权的目标。未经许可的扫描是违法的。

## 用法

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## 模板

模板位于独立的仓库中，按类别整理：
**https://github.com/slayzbsss/hakscan-templates**

## 我们的使命

传统扫描器笨重且封闭。Hakscan 保持一个微小而开放的引擎，检测逻辑写在可读的模板中。

## 许可证

Hakscan 基于 MIT 许可证发布。 — [LICENSE.md](LICENSE.md)
