<h1 align="center"><img src="assets/logo.svg" alt="Hakscan" width="600"></h1>

<div align="center">

  <a href="README.md">`English`</a> •
  <a href="README_FR.md">`Français`</a> •
  <a href="README_ES.md">`Español`</a> •
  `Português` •
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

**Hakscan é um scanner de vulnerabilidades rápido e autônomo baseado em templates JSON e YAML. Um único binário nativo, sem dependências.**

- Formato JSON/YAML simples para criar suas detecções.
- Motor web: cabeçalhos, TLS, CORS, exposições, testes ativos (XSS, SQLi, SSTI, LFI, injeção de comando, CRLF, open redirect).
- Motor de arquivos: parser de AndroidManifest.xml e scanner de segredos (APK/JAR/ZIP, código).
- Executa seus templates JSON e os templates YAML da comunidade.
- Leve, multiplataforma, pronto para CI/CD.

## Começar

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
# Arch Linux
yay -S hakscan-bin
sudo pacman -U https://github.com/slayzbsss/Hakscan/releases/latest/download/hakscan_4.3_linux_amd64.pkg.tar.zst
```

> [!IMPORTANT]
> Use apenas contra alvos que você possui ou com autorização por escrito. Escanear sem permissão é ilegal.

## Uso

```console
hakscan https://example.com
hakscan -l urls.txt
hakscan app.apk
hakscan -t auto https://example.com
```

## Templates

Os templates ficam num repositório dedicado, por categoria:
**https://github.com/slayzbsss/hakscan-templates**

## Nossa missão

Scanners tradicionais são pesados e fechados. O Hakscan mantém um motor minúsculo e aberto onde a detecção vive em templates legíveis.

## Licença

Hakscan é distribuído sob a licença MIT. — [LICENSE.md](LICENSE.md)
