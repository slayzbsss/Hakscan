![hakscan](assets/hakscan-cover.png)

<div align="center">

  <a href="README.md">`English`</a> •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_ES.md">`Español`</a> •
  <a href="README_PT-BR.md">`Português`</a> •
  <a href="README_DE.md">`Deutsch`</a> •
  <a href="README_IT.md">`Italiano`</a> •
  <a href="README_CN.md">`中文`</a> •
  `日本語` •
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

**Hakscan はシンプルな JSON / YAML テンプレートを用いた、高速で自己完結型の脆弱性スキャナーです。依存関係のない単一ネイティブバイナリです。**

- 独自の検出を作成できるシンプルな JSON/YAML 形式。
- Web エンジン：ヘッダー、TLS、CORS、情報露出、能動的テスト（XSS、SQLi、SSTI、LFI、コマンドインジェクション、CRLF、オープンリダイレクト）。
- ファイルエンジン：AndroidManifest.xml パーサーとシークレットスキャナー（APK/JAR/ZIP、ソース）。
- 独自の JSON テンプレートとコミュニティの YAML テンプレートを実行。
- 軽量・クロスプラットフォーム・CI/CD 対応。

## はじめに

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> 所有する、または書面による許可を得た対象にのみ使用してください。許可のないスキャンは違法です。

## 使い方

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## テンプレート

テンプレートは専用リポジトリにカテゴリ別で置かれています：
**https://github.com/slayzbsss/hakscan-templates**

## 私たちのミッション

従来のスキャナーは重く閉鎖的です。Hakscan は小さく開かれたエンジンを保ち、検出は読みやすいテンプレートに記述します。

## ライセンス

Hakscan は MIT ライセンスで配布されています。 — [LICENSE.md](LICENSE.md)
