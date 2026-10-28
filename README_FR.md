<h1 align="center">
  <img src="assets/logo.svg" alt="Hakscan" width="420"></a>
</h1>

<p align="center">
<a href="README.md">English</a> • <strong>Français</strong>
</p>

---

Hakscan est un scanner de vulnérabilités rapide et autonome, basé sur de simples
templates JSON et YAML. Il vous permet de concevoir vos propres scénarios de
détection, et se présente sous la forme d'un unique binaire natif, sans aucune
dépendance.

- Binaire natif unique (Go) — sans runtime, sans dépendance, multi-plateforme.
- Formats de templates simples pour créer et personnaliser vos détections.
- Moteur web : en-têtes, TLS, CORS, expositions, et tests actifs sur les
  paramètres (XSS, SQLi, SSTI, LFI, injection de commande, CRLF, open redirect).
- Moteur fichiers : parseur `AndroidManifest.xml` intégré et scanner de
  secrets pour APK/AAB/JAR/ZIP et arborescences de code.
- Exécute vos propres templates JSON et les templates YAML de la communauté.
- Léger et adapté à la CI/CD, avec sortie JSON et releases automatisées.

## Pour commencer

Installation avec Go :

```console
go install -v github.com/slayzbsss/Hakscan/cmd/hakscan@latest
```

Ou téléchargez un binaire pré-compilé depuis la page
[releases](https://github.com/slayzbsss/Hakscan/releases)
(`linux`, `darwin`, `windows` — `amd64`/`arm64`) :

```console
chmod +x hakscan
./hakscan -h
```

Ou compilez depuis les sources :

```console
git clone https://github.com/slayzbsss/Hakscan.git
cd Hakscan && make build
```

> [!IMPORTANT]
> N'utilisez Hakscan que sur des cibles que vous possédez ou pour lesquelles
> vous avez une autorisation écrite explicite (ex. le périmètre d'un programme
> de bug bounty). Scanner sans permission est illégal.

## Utilisation

### Scan d'une cible

```console
hakscan https://example.com
hakscan -u "https://example.com/page?id=1" --json rapport.json
hakscan --passive https://example.com
```

### Scan de plusieurs cibles

```console
hakscan -l urls.txt
```

### Analyse de fichiers & APK

```console
hakscan app.apk
hakscan ./dossier-source/
```

### Scan avec vos propres templates

```console
hakscan -u https://example.com -t /chemin/vers/vos-templates/
hakscan update-templates && hakscan -t auto https://example.com
```

## Templates et communauté

Les templates Hakscan vivent dans un dépôt dédié, trié par catégorie :
**https://github.com/slayzbsss/hakscan-templates**

- `kind: http` — checks web testés contre une réponse HTTP.
- `kind: secret` — signatures regex pour le moteur fichiers/APK.

Hakscan exécute aussi les templates YAML de la communauté (sous-ensemble HTTP).

## Notre mission

Les scanners traditionnels sont lourds, fermés et difficiles à étendre. Hakscan
adopte une autre approche : un moteur minuscule, ouvert et sans dépendance, où
la logique de détection vit dans des templates lisibles — pour encoder ce que
vous apprenez d'une cible et le rejouer partout, en local comme en CI.

## Licence

Hakscan est distribué sous [licence MIT](LICENSE.md).
