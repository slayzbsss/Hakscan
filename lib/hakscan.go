package hakscan

import (
	"time"

	"github.com/slayzbsss/Hakscan/pkg/file"
	"github.com/slayzbsss/Hakscan/pkg/output"
	"github.com/slayzbsss/Hakscan/pkg/web"
)

// ScanWeb runs the web engine against target and returns the report.
func ScanWeb(target string, active bool, templates string, delay time.Duration) *output.Report {
	return web.NewWebScanner(target, delay, templates, active).Run()
}

// ScanFile runs the file/APK/DEX/ELF engine against a path and returns the report.
func ScanFile(path string) *output.Report {
	return file.AnalyzeFile(path)
}
