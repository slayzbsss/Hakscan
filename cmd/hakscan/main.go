package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/slayzbsss/Hakscan/pkg/file"
	"github.com/slayzbsss/Hakscan/pkg/httpx"
	"github.com/slayzbsss/Hakscan/pkg/output"
	"github.com/slayzbsss/Hakscan/pkg/update"
	"github.com/slayzbsss/Hakscan/pkg/web"
)

var version = httpx.Version

func popOpt(args *[]string, names ...string) string {
	a := *args
	for _, name := range names {
		for i := 0; i < len(a); i++ {
			if a[i] == name && i+1 < len(a) {
				val := a[i+1]
				a = append(a[:i], a[i+2:]...)
				*args = a
				return val
			}
		}
	}
	return ""
}

func popFlag(args *[]string, names ...string) bool {
	a := *args
	hit := false
	for _, name := range names {
		out := a[:0]
		for _, x := range a {
			if x == name {
				hit = true
				continue
			}
			out = append(out, x)
		}
		a = out
	}
	*args = a
	return hit
}

const helpText = `Hakscan is a fast, template-based web & file vulnerability scanner
focused on simplicity and shipping as a single native binary.

Usage:
  hakscan [flags] <target>

Flags:
TARGET:
   -u, --url string    target URL/host to scan
   -l, --list string   path to file with a list of targets (one per line)

TEMPLATES:
   -t, --templates string   run JSON/YAML templates from a directory ("auto" for community templates)
       --passive            passive mode - no active injection tests (headers/TLS/exposures only)

OUTPUT:
   -o, --json string   write JSON report to the given file

CONFIGURATIONS:
       --delay int     delay between requests in milliseconds (default 300)

FILE ENGINE:
   hakscan <file>      analyze an APK/AAB/JAR/ZIP, DEX or ELF
                       (manifest, DEX & native-lib strings, assets, secrets)
   hakscan <dir>       recursively analyze a directory

UPDATE:
   update-templates    download / update community YAML templates

DEBUG:
   version                     show hakscan version
       --disable-update-check  (-duc) skip the GitHub version check at startup
   -h, --help                  show this help message

EXAMPLES:
Run a web scan on a single host:
   $ hakscan https://example.com

Run with custom templates:
   $ hakscan -t ./templates/ https://example.com

Run community YAML templates:
   $ hakscan -t auto https://example.com

Scan many targets with a JSON report:
   $ hakscan -l targets.txt -o report.json

Analyze a mobile app:
   $ hakscan app.apk

Authorized targets only. Scanning without permission is illegal.`

const bannerArt = "\n    __          __                       \n   / /_  ____ _/ /________________ _____ \n  / __ \\/ __ `/ //_/ ___/ ___/ __ `/ __ \\\n / / / / /_/ / ,< (__  ) /__/ /_/ / / / /\n/_/ /_/\\__,_/_/|_/____/\\___/\\__,_/_/ /_/    %s\n\n                 slayzbs\n"

func showBanner() {
	fmt.Fprintf(os.Stderr, bannerArt, "v"+version)
}

func showStartupInfo(noUpdate bool) int {
	ui := update.FetchLatest(noUpdate)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "[INF] Current hakscan version: v%s%s\n", version, update.VerStatus(version, ui.EngineLatest))
	dir := update.NucleiTemplatesDir()
	n := update.CountTemplates(dir)
	if n == 0 {
		fmt.Fprintln(os.Stderr, "[INF] No templates installed yet - run: hakscan update-templates")
		return 0
	}
	tplVer, tplStatus := ui.TemplatesLatest, " (latest)"
	if tplVer == "" {
		tplVer, tplStatus = update.TemplatesVersion(dir), "" // offline fallback: install date
	}
	fmt.Fprintf(os.Stderr, "[INF] Current hakscan-templates version: %s%s\n", tplVer, tplStatus)
	fmt.Fprintf(os.Stderr, "[INF] New templates added in latest release: %d\n", update.NewAdditions(dir))
	return n
}

func main() {
	start := time.Now()
	args := os.Args[1:]
	explicitHelp := len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help")
	isVersion := len(args) > 0 && (args[0] == "version" || args[0] == "-version" || args[0] == "--version")

	if explicitHelp {
		fmt.Println(helpText)
		return
	}
	noUpdate := popFlag(&args, "-duc", "--disable-update-check")
	if !isVersion {
		showBanner()
		n := showStartupInfo(noUpdate)
		if len(args) == 0 {
			// no target: mirror nuclei's empty run instead of dumping help
			if n > 0 {
				fmt.Fprintf(os.Stderr, "[INF] Templates loaded for current scan: %d\n", n)
				fmt.Fprintf(os.Stderr, "[INF] Executing %d templates from slayzbsss/hakscan-templates\n", n)
			}
			fmt.Fprintf(os.Stderr, "[INF] Scan completed in %s. No results found.\n", time.Since(start).Round(time.Millisecond))
			return
		}
	}
	switch args[0] {
	case "version", "-version", "--version":
		fmt.Printf("Hakscan v%s\n", version)
		return
	case "update-templates", "update", "ut":
		os.Exit(update.UpdateTemplates())
	}

	jsonOut := popOpt(&args, "--json", "-o")
	delayStr := popOpt(&args, "--delay")
	templates := popOpt(&args, "-t", "--templates")
	passive := popFlag(&args, "--passive")
	listFile := popOpt(&args, "-l", "-list", "--list")
	target := popOpt(&args, "-u", "--url")

	delay := 300 * time.Millisecond
	if delayStr != "" {
		if d, err := time.ParseDuration(delayStr + "ms"); err == nil {
			delay = d
		}
	}

	if listFile != "" {
		data, err := os.ReadFile(listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot read list %s: %v\n", listFile, err)
			os.Exit(2)
		}
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			rep := web.NewWebScanner(t, delay, templates, !passive).Run()
			rep.Print()
			if jsonOut != "" {
				output.WriteJSON(rep, jsonOut)
			}
		}
		return
	}

	if len(args) > 0 && args[0] == "file" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "[!] usage: hakscan file <path>")
			os.Exit(2)
		}
		os.Exit(file.AnalyzeFileTarget(args[1], jsonOut, templates))
	}

	if target == "" {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				target = a
				break
			}
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "[!] No target. See: hakscan -h")
		os.Exit(2)
	}

	if _, err := os.Stat(target); err == nil {
		os.Exit(file.AnalyzeFileTarget(target, jsonOut, templates))
	}

	rep := web.NewWebScanner(target, delay, templates, !passive).Run()
	rep.Print()
	if jsonOut != "" {
		output.WriteJSON(rep, jsonOut)
	}
}
