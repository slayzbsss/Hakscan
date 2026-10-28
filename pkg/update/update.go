package update

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/slayzbsss/Hakscan/pkg/httpx"
)

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

func HakscanHome() string { return filepath.Join(homeDir(), ".hakscan") }

func NucleiTemplatesDir() string { return filepath.Join(HakscanHome(), "nuclei-templates") }

const TemplatesZip = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"

// ===========================================================================
//  Result model
// ===========================================================================

func UpdateTemplates() int {
	os.MkdirAll(HakscanHome(), 0755)
	fmt.Println("[*] Downloading community YAML templates (MIT, (c) ProjectDiscovery - see NOTICE)...")
	tmp := filepath.Join(os.TempDir(), "hakscan_templates.zip")
	req, _ := http.NewRequest("GET", TemplatesZip, nil)
	req.Header.Set("User-Agent", httpx.UserAgent)
	resp, err := (&http.Client{Timeout: 180 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Download failed: %v\n", err)
		return 1
	}
	out, err := os.Create(tmp)
	if err != nil {
		resp.Body.Close()
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return 1
	}
	io.Copy(out, resp.Body)
	resp.Body.Close()
	out.Close()
	defer os.Remove(tmp)

	staging := filepath.Join(HakscanHome(), "_staging")
	os.RemoveAll(staging)
	if err := unzipSafe(tmp, staging); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Extraction failed: %v\n", err)
		return 1
	}
	extracted := filepath.Join(staging, "nuclei-templates-main")
	if st, e := os.Stat(extracted); e != nil || !st.IsDir() {
		entries, _ := os.ReadDir(staging)
		for _, en := range entries {
			if en.IsDir() {
				extracted = filepath.Join(staging, en.Name())
				break
			}
		}
	}
	os.RemoveAll(NucleiTemplatesDir())
	if err := os.Rename(extracted, NucleiTemplatesDir()); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return 1
	}
	os.RemoveAll(staging)
	count := 0
	filepath.Walk(NucleiTemplatesDir(), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			e := strings.ToLower(filepath.Ext(p))
			if e == ".yaml" || e == ".yml" {
				count++
			}
		}
		return nil
	})
	fmt.Printf("[*] %d templates installed in %s\n", count, NucleiTemplatesDir())
	fmt.Println("    Templates (c) ProjectDiscovery, MIT license.")
	fmt.Println("    Run them with:  hakscan -t auto https://target.com")
	return 0
}

func unzipSafe(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	destAbs, _ := filepath.Abs(dest)
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		ta, _ := filepath.Abs(target)
		if !strings.HasPrefix(ta, destAbs+string(os.PathSeparator)) && ta != destAbs {
			return fmt.Errorf("unsafe path: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		rc, e := f.Open()
		if e != nil {
			return e
		}
		w, e := os.Create(target)
		if e != nil {
			rc.Close()
			return e
		}
		io.Copy(w, io.LimitReader(rc, maxMember))
		w.Close()
		rc.Close()
	}
	return nil
}

// ===========================================================================
//  helpers + CLI
// ===========================================================================

func CountTemplates(dir string) int {
	n := 0
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml":
			n++
		}
		return nil
	})
	return n
}

func TemplatesVersion(dir string) string {
	if fi, err := os.Stat(dir); err == nil {
		return fi.ModTime().Format("2006.01.02")
	}
	return "unknown"
}

func NewAdditions(dir string) int {
	data, err := os.ReadFile(filepath.Join(dir, ".new-additions"))
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
			n++
		}
	}
	return n
}

// --- live update check (queried from GitHub, cached to respect the API rate limit) ---

type Info struct {
	CheckedAt       time.Time `json:"checked_at"`
	EngineLatest    string    `json:"engine_latest"`
	TemplatesLatest string    `json:"templates_latest"`
}

func updateCachePath() string { return filepath.Join(HakscanHome(), ".update-check.json") }

// githubLatestTag returns the tag_name of the latest release of owner/repo, or "".

func GithubLatestTag(repo string) string {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", httpx.UserAgent)
	resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil {
		return ""
	}
	return r.TagName
}

// fetchLatest returns the latest engine/templates tags, hitting GitHub at most
// once every 6h and falling back to the cache when offline or disabled.

func FetchLatest(disable bool) Info {
	var ui Info
	if b, err := os.ReadFile(updateCachePath()); err == nil {
		_ = json.Unmarshal(b, &ui)
	}
	if disable || (ui.EngineLatest != "" && time.Since(ui.CheckedAt) < 6*time.Hour) {
		return ui
	}
	eng := GithubLatestTag("slayzbsss/Hakscan")
	tpl := GithubLatestTag("projectdiscovery/nuclei-templates")
	if eng == "" && tpl == "" {
		return ui // offline: keep whatever cache we had
	}
	if eng == "" {
		eng = ui.EngineLatest
	}
	if tpl == "" {
		tpl = ui.TemplatesLatest
	}
	ui = Info{CheckedAt: time.Now(), EngineLatest: eng, TemplatesLatest: tpl}
	if b, err := json.Marshal(ui); err == nil {
		_ = os.MkdirAll(HakscanHome(), 0o755)
		_ = os.WriteFile(updateCachePath(), b, 0o644)
	}
	return ui
}

// verStatus compares current to the latest tag and returns " (latest)" or
// " (outdated, latest X)"; empty when the latest is unknown.

func VerStatus(current, latest string) string {
	if latest == "" {
		return ""
	}
	if strings.TrimPrefix(current, "v") == strings.TrimPrefix(latest, "v") {
		return " (latest)"
	}
	return " (outdated, latest " + latest + ")"
}

// showStartupInfo prints the nuclei-style [INF] startup block and returns the
// number of installed templates. It queries GitHub (unless noUpdate) for the
// latest engine/templates versions.

const maxMember = 25 * 1024 * 1024
