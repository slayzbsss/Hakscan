![hakscan](assets/banner.png)

<div align="center">

  <a href="README.md">`English`</a> •
  `Français` •
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

**Hakscan est un scanner de vulnérabilités rapide et autonome, basé sur de simples templates JSON et YAML. Un seul binaire natif, sans dépendance.**

- Format JSON/YAML simple pour créer vos détections.
- Moteur web : en-têtes, TLS, CORS, expositions, tests actifs (XSS, SQLi, SSTI, LFI, injection de commande, CRLF, open redirect).
- Moteur fichiers : parseur AndroidManifest.xml et scanner de secrets (APK/JAR/ZIP, code).
- Exécute vos templates JSON et les templates YAML de la communauté.
- Léger, multi-plateforme, intégrable en CI/CD.

## Pour commencer

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> À n'utiliser que sur des cibles que vous possédez ou avec autorisation écrite. Scanner sans permission est illégal.

## Utilisation

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## Templates

Les templates vivent dans un dépôt dédié, trié par catégorie :
**https://github.com/slayzbsss/hakscan-templates**

## Notre mission

Les scanners traditionnels sont lourds et fermés. Hakscan garde un moteur minuscule et ouvert où la détection vit dans des templates lisibles.

## Licence

Hakscan est distribué sous licence MIT. — [LICENSE.md](LICENSE.md)
