# Packaging

## AUR (Arch Linux, `yay`)

Two packages are provided in `packaging/aur/`:

- `hakscan-bin` — installs the prebuilt release binary (fast).
- `hakscan` — builds from source with Go.

### Publish to the AUR (one-time, by the maintainer)

The AUR is a separate git service; publishing needs your own AUR account.

1. Create an account at <https://aur.archlinux.org> and add your SSH public key
   under *My Account → SSH Public Key*.
2. Clone the (empty) AUR repo and add the package files:

   ```console
   git clone ssh://aur@aur.archlinux.org/hakscan-bin.git
   cp packaging/aur/hakscan-bin/{PKGBUILD,.SRCINFO} hakscan-bin/
   cd hakscan-bin
   git add PKGBUILD .SRCINFO
   git commit -m "hakscan-bin 4.2-1"
   git push
   ```

3. Anyone can then install it:

   ```console
   yay -S hakscan-bin
   ```

Repeat the same with `packaging/aur/hakscan/` for the source package.

### Updating on a new release

Bump `pkgver`, refresh `sha256sums` from the release `checksums.txt`, regenerate
`.SRCINFO` (`makepkg --printsrcinfo > .SRCINFO`), commit and push.

### Optional: automate via goreleaser

goreleaser can push the AUR package automatically on each tag with an `aurs:`
block in `.goreleaser.yml`, using an AUR SSH key stored as the `AUR_KEY`
GitHub Actions secret. It is left disabled here so releases do not require that
secret.

## Debian / RPM / Alpine

`.deb`, `.rpm` and `.apk` packages are built automatically by goreleaser and
attached to each GitHub release.

## Homebrew / Scoop

Can be added via goreleaser `brews:` / `scoops:` blocks pointing at a tap repo
(`slayzbsss/homebrew-tap`) — requires a tap repository and a token.
