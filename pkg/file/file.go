package file

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/slayzbsss/Hakscan/pkg/output"
	"github.com/slayzbsss/Hakscan/pkg/update"
)

const maxMember = 25 * 1024 * 1024

type secretPat struct {
	name, sev string
	re        *regexp.Regexp
}

var secretPatterns = []secretPat{
	{"Private key block (PEM)", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"AWS Access Key ID", "high", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"AWS Secret Access Key", "high", regexp.MustCompile(`(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`)},
	{"Google API key", "high", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"Google OAuth client", "medium", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
	{"GCP service account", "high", regexp.MustCompile(`"type"\s*:\s*"service_account"`)},
	{"GitHub token", "high", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36}\b`)},
	{"GitLab token", "high", regexp.MustCompile(`\bglpat-[0-9A-Za-z\-_]{20}\b`)},
	{"Slack token", "high", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"Slack webhook", "medium", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`)},
	{"Discord webhook", "medium", regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`)},
	{"Telegram bot token", "medium", regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`)},
	{"Stripe live key", "critical", regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,}`)},
	{"Twilio SID", "medium", regexp.MustCompile(`\bAC[a-z0-9]{32}\b`)},
	{"SendGrid API key", "high", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)},
	{"npm token", "high", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"JWT", "low", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"Firebase DB URL", "medium", regexp.MustCompile(`[a-z0-9.-]+\.firebaseio\.com`)},
	{"Basic auth in URL", "high", regexp.MustCompile(`https?://[^/\s:@]+:[^/\s:@]+@[A-Za-z0-9.-]+`)},
	{"DB connection string", "high", regexp.MustCompile(`\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'"]+`)},
	{"Hardcoded secret (assignment)", "low", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|passwd|password|token|private[_-]?key|access[_-]?key)['"]?\s*[:=]\s*['"][^'"\s]{8,}['"]`)},
}

var extraSecretPatterns []secretPat

var urlPattern = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)

var ipPattern = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b`)

var printableRun = regexp.MustCompile(`[\x20-\x7e]{6,}`)

var dangerousPerms = map[string]bool{
	"android.permission.READ_SMS": true, "android.permission.SEND_SMS": true,
	"android.permission.RECEIVE_SMS": true, "android.permission.READ_CONTACTS": true,
	"android.permission.ACCESS_FINE_LOCATION": true, "android.permission.RECORD_AUDIO": true,
	"android.permission.CAMERA": true, "android.permission.READ_EXTERNAL_STORAGE": true,
	"android.permission.WRITE_EXTERNAL_STORAGE": true, "android.permission.READ_CALL_LOG": true,
	"android.permission.READ_PHONE_STATE": true, "android.permission.SYSTEM_ALERT_WINDOW": true,
	"android.permission.REQUEST_INSTALL_PACKAGES": true,
}

func looksBinary(data []byte) bool {
	n := len(data)
	if n > 4096 {
		n = 4096
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func extractStrings(data []byte) string {
	var parts []string
	for _, m := range printableRun.FindAll(data, -1) {
		parts = append(parts, string(m))
	}
	return strings.Join(parts, "\n")
}

func textFromBytes(data []byte) string {
	if looksBinary(data) {
		return extractStrings(data)
	}
	return string(data)
}

type seenKey struct{ name, snippet, loc string }

func scanSecrets(text, location string, rep *output.Report, seen map[seenKey]bool) {
	all := append(append([]secretPat{}, secretPatterns...), extraSecretPatterns...)
	for _, p := range all {
		for _, m := range p.re.FindAllString(text, -1) {
			sn := m
			if len(sn) > 40 {
				sn = sn[:40]
			}
			k := seenKey{p.name, sn, location}
			if seen[k] {
				continue
			}
			seen[k] = true
			rep.Add("Potential secret: "+p.name, p.sev, "Possibly hardcoded credential/key.", location, output.Mask(m))
		}
	}
}

func loadSecretTemplates(dir string) []secretPat {
	var out []secretPat
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return out
	}
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		var t map[string]interface{}
		if json.Unmarshal(b, &t) != nil {
			return nil
		}
		if kind, _ := t["kind"].(string); kind != "secret" {
			return nil
		}
		rx, _ := t["regex"].(string)
		if rx == "" {
			return nil
		}
		re, e := regexp.Compile(rx)
		if e != nil {
			return nil
		}
		name, _ := t["name"].(string)
		if name == "" {
			name = "custom secret"
		}
		sev, _ := t["severity"].(string)
		if sev == "" {
			sev = "low"
		}
		out = append(out, secretPat{name, sev, re})
		return nil
	})
	return out
}

// ===========================================================================
//  AndroidManifest.xml (AXML) parser
// ===========================================================================

type axmlElement struct {
	tag   string
	attrs map[string]string
}

func parseAXML(d []byte) (elems []axmlElement, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("axml parse panic")
		}
	}()
	if len(d) < 8 || binary.LittleEndian.Uint16(d[0:2]) != 0x0003 {
		return nil, fmt.Errorf("invalid AXML header")
	}
	var strs []string
	off, n := 8, len(d)
	readStr := func(p int, utf8 bool) string {
		if p < 0 || p >= len(d) {
			return ""
		}
		if utf8 {
			if d[p]&0x80 != 0 {
				p += 2
			} else {
				p++
			}
			blen := int(d[p])
			if blen&0x80 != 0 {
				blen = (blen&0x7f)<<8 | int(d[p+1])
				p += 2
			} else {
				p++
			}
			if p+blen > len(d) {
				return ""
			}
			return string(d[p : p+blen])
		}
		ln := int(binary.LittleEndian.Uint16(d[p:]))
		if ln&0x8000 != 0 {
			ln = (ln&0x7fff)<<16 | int(binary.LittleEndian.Uint16(d[p+2:]))
			p += 4
		} else {
			p += 2
		}
		if p+ln*2 > len(d) {
			return ""
		}
		u16 := make([]uint16, ln)
		for i := 0; i < ln; i++ {
			u16[i] = binary.LittleEndian.Uint16(d[p+i*2:])
		}
		return string(utf16Decode(u16))
	}
	strAt := func(idx uint32) string {
		if idx != 0xFFFFFFFF && int(idx) < len(strs) {
			return strs[idx]
		}
		return ""
	}
	for off+8 <= n {
		ctype := binary.LittleEndian.Uint16(d[off:])
		csize := int(binary.LittleEndian.Uint32(d[off+4:]))
		if csize < 8 || off+csize > n {
			break
		}
		switch ctype {
		case 0x0001: // string pool
			count := int(binary.LittleEndian.Uint32(d[off+8:]))
			flags := binary.LittleEndian.Uint32(d[off+16:])
			stringsStart := int(binary.LittleEndian.Uint32(d[off+20:]))
			utf8 := flags&0x0100 != 0
			offsetsBase := off + 28
			dataBase := off + stringsStart
			strs = make([]string, 0, count)
			for i := 0; i < count; i++ {
				if offsetsBase+i*4+4 > len(d) {
					break
				}
				so := int(binary.LittleEndian.Uint32(d[offsetsBase+i*4:]))
				strs = append(strs, readStr(dataBase+so, utf8))
			}
		case 0x0102: // start element
			if off+28 > n {
				break
			}
			nameIdx := binary.LittleEndian.Uint32(d[off+20:])
			attrStart := int(binary.LittleEndian.Uint16(d[off+24:]))
			attrCount := int(binary.LittleEndian.Uint16(d[off+28:]))
			attrs := map[string]string{}
			base := off + 16 + attrStart
			for i := 0; i < attrCount; i++ {
				a := base + i*20
				if a+20 > len(d) {
					break
				}
				aname := binary.LittleEndian.Uint32(d[a+4:])
				raw := binary.LittleEndian.Uint32(d[a+8:])
				dtype := d[a+15]
				ddata := binary.LittleEndian.Uint32(d[a+16:])
				attrs[strAt(aname)] = typedValue(raw, dtype, ddata, strs, strAt)
			}
			elems = append(elems, axmlElement{tag: strAt(nameIdx), attrs: attrs})
		}
		off += csize
	}
	return elems, nil
}

func typedValue(raw uint32, dtype byte, data uint32, strs []string, strAt func(uint32) string) string {
	if raw != 0xFFFFFFFF {
		if s := strAt(raw); s != "" {
			return s
		}
	}
	switch dtype {
	case 0x12:
		if data != 0 {
			return "true"
		}
		return "false"
	case 0x03:
		return strAt(data)
	}
	return fmt.Sprintf("%d", int32(data))
}

func utf16Decode(u []uint16) []rune {
	var out []rune
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c >= 0xD800 && c <= 0xDBFF && i+1 < len(u) {
			c2 := u[i+1]
			if c2 >= 0xDC00 && c2 <= 0xDFFF {
				out = append(out, rune((int(c-0xD800)<<10)+int(c2-0xDC00)+0x10000))
				i++
				continue
			}
		}
		out = append(out, rune(c))
	}
	return out
}

// ===========================================================================
//  FILE ENGINE - archives, directories
// ===========================================================================

var archiveExt = map[string]bool{".apk": true, ".aab": true, ".xapk": true, ".ipa": true,
	".jar": true, ".war": true, ".zip": true}

func analyzeManifest(data []byte, rep *output.Report) {
	elems, err := parseAXML(data)
	if err != nil {
		rep.Add("AndroidManifest not parsed", "info", "AXML parsing failed; string analysis only.", "AndroidManifest.xml")
		return
	}
	var perms []string
	for _, e := range elems {
		switch e.tag {
		case "application":
			if e.attrs["debuggable"] == "true" {
				rep.Add("Debuggable APK", "high", `android:debuggable="true": debugging possible in production.`, "application")
			}
			if e.attrs["allowBackup"] == "true" {
				rep.Add("Backup allowed (allowBackup)", "low", `android:allowBackup="true": data extractable via adb.`, "application")
			}
			if e.attrs["usesCleartextTraffic"] == "true" {
				rep.Add("Cleartext traffic allowed", "medium", `android:usesCleartextTraffic="true": plain HTTP permitted.`, "application")
			}
			if e.attrs["testOnly"] == "true" {
				rep.Add("testOnly flag set", "low", `android:testOnly="true": debug/test build.`, "application")
			}
			if _, ok := e.attrs["networkSecurityConfig"]; ok {
				rep.Add("Network Security Config present", "info", "Inspect it: may allow cleartext or custom CAs.", "application")
			}
		case "activity", "service", "receiver", "provider":
			if e.attrs["exported"] == "true" {
				if _, ok := e.attrs["permission"]; !ok {
					rep.Add("Exported component without permission: "+e.tag, "medium", "Reachable by other apps with no protection.", e.attrs["name"])
				}
			}
		case "uses-permission":
			if n := e.attrs["name"]; n != "" {
				perms = append(perms, n)
			}
		case "meta-data":
			val := e.attrs["value"]
			nm := e.attrs["name"]
			if regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`).MatchString(val) || strings.Contains(strings.ToUpper(nm), "API_KEY") {
				ev := nm
				if val != "" {
					ev = output.Mask(val)
				}
				rep.Add("Embedded API key in manifest meta-data", "high", "meta-data '"+nm+"' may hold an API key.", "meta-data", ev)
			}
		}
	}
	var dang []string
	for _, p := range perms {
		if dangerousPerms[p] {
			dang = append(dang, p)
		}
	}
	if len(dang) > 0 {
		sort.Strings(dang)
		if len(dang) > 12 {
			dang = dang[:12]
		}
		rep.Add(fmt.Sprintf("Dangerous permissions requested (%d)", len(dang)), "info", "App requests sensitive permissions.", "", strings.Join(dang, ", "))
	}
}

func isDex(data []byte) bool { return bytes.HasPrefix(data, []byte("dex\n")) }

func isELF(data []byte) bool { return bytes.HasPrefix(data, []byte("\x7fELF")) }

// collectURLsIPs extracts referenced hostnames and hardcoded IPs from a blob,
// filtering out framework/noise hosts and non-routable IPs.

func collectURLsIPs(data []byte, urls, ips map[string]bool) {
	for _, m := range urlPattern.FindAll(data, -1) {
		if u, e := url.Parse(string(m)); e == nil && u.Hostname() != "" {
			h := u.Hostname()
			if !strings.HasSuffix(h, ".google.com") && !strings.HasSuffix(h, ".android.com") &&
				!strings.HasSuffix(h, ".w3.org") && !strings.Contains(h, "schemas.android.com") {
				urls[h] = true
			}
		}
	}
	for _, m := range ipPattern.FindAll(data, -1) {
		ip := string(m)
		if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "0.") && !strings.HasPrefix(ip, "255.") {
			ips[ip] = true
		}
	}
}

// uleb128 decodes an unsigned LEB128 value, returning it and the bytes read.

func uleb128(b []byte) (uint32, int) {
	var result uint32
	var shift uint
	for i := 0; i < len(b) && i < 5; i++ {
		result |= uint32(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return result, 0
}

// dexStrings parses the Dalvik string_ids table of a .dex blob and returns the
// decoded strings (MUTF-8 read as raw bytes, which is fine for secret matching).

func dexStrings(data []byte) []string {
	if len(data) < 0x70 || !isDex(data) {
		return nil
	}
	le := binary.LittleEndian
	size := le.Uint32(data[0x38:])
	off := le.Uint32(data[0x3C:])
	if size > 3_000_000 { // sanity cap against corrupt/hostile headers
		size = 3_000_000
	}
	out := make([]string, 0, size)
	for i := uint32(0); i < size; i++ {
		p := int(off) + int(i)*4
		if p+4 > len(data) {
			break
		}
		so := int(le.Uint32(data[p:]))
		if so <= 0 || so >= len(data) {
			continue
		}
		_, n := uleb128(data[so:]) // skip the utf16 length prefix
		idx := so + n
		end := idx
		for end < len(data) && data[end] != 0 {
			end++
		}
		if end > idx {
			out = append(out, string(data[idx:end]))
		}
	}
	return out
}

// analyzeDex parses a Dalvik executable and scans its string table for secrets
// and referenced endpoints.

func analyzeDex(data []byte, location string, rep *output.Report, seen map[seenKey]bool, urls, ips map[string]bool) {
	strs := dexStrings(data)
	if strs == nil {
		return
	}
	rep.Add(fmt.Sprintf("Android DEX analyzed (%d strings)", len(strs)), "info",
		"Parsed the Dalvik string table.", location)
	text := strings.Join(strs, "\n")
	scanSecrets(text, location, rep, seen)
	collectURLsIPs([]byte(text), urls, ips)
}

// elfStringSections holds the sections most likely to carry constants/strings.

var elfStringSections = map[string]bool{
	".rodata": true, ".data": true, ".data.rel.ro": true,
	".dynstr": true, ".strtab": true, ".comment": true, ".note": true,
}

// analyzeELF parses an ELF binary (standalone or lib/*.so inside an APK),
// reports its metadata, and scans string/data sections for secrets and endpoints.

func analyzeELF(data []byte, location string, rep *output.Report, seen map[seenKey]bool, urls, ips map[string]bool) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer f.Close()
	meta := strings.TrimPrefix(f.Machine.String(), "EM_") + " " + strings.TrimPrefix(f.Type.String(), "ET_")
	if f.Section(".symtab") == nil {
		meta += ", stripped"
	}
	rep.Add("ELF binary analyzed ("+meta+")", "info", "Parsed ELF sections.", location)
	var buf []byte
	for _, s := range f.Sections {
		if !elfStringSections[s.Name] || s.Size == 0 || s.Size > maxMember {
			continue
		}
		if b, e := s.Data(); e == nil {
			buf = append(buf, b...)
		}
	}
	if len(buf) == 0 {
		return
	}
	text := textFromBytes(buf)
	scanSecrets(text, location, rep, seen)
	collectURLsIPs(buf, urls, ips)
}

func analyzeArchive(path string, rep *output.Report) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		rep.Add("Unreadable archive", "info", "Not a valid ZIP.", filepath.Base(path))
		return
	}
	defer zr.Close()
	seen := map[seenKey]bool{}
	urls := map[string]bool{}
	ips := map[string]bool{}
	dexCount, elfCount, assetCount := 0, 0, 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 > maxMember {
			continue
		}
		rc, e := f.Open()
		if e != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, maxMember))
		rc.Close()
		if filepath.Base(f.Name) == "AndroidManifest.xml" && !strings.Contains(f.Name, "/") {
			analyzeManifest(data, rep)
		}
		if strings.HasPrefix(f.Name, "assets/") {
			assetCount++
		}
		switch {
		case isDex(data):
			dexCount++
			analyzeDex(data, f.Name, rep, seen, urls, ips)
		case isELF(data):
			elfCount++
			analyzeELF(data, f.Name, rep, seen, urls, ips)
		}
		scanSecrets(textFromBytes(data), f.Name, rep, seen)
		collectURLsIPs(data, urls, ips)
	}
	if dexCount > 0 {
		rep.Add(fmt.Sprintf("Android application (%d DEX file(s))", dexCount), "info", "Dalvik bytecode found and analyzed.", "classes.dex")
	}
	if elfCount > 0 {
		rep.Add(fmt.Sprintf("Native ELF libraries bundled (%d)", elfCount), "info", "lib/*.so native code found and analyzed.", "lib/")
	}
	if assetCount > 0 {
		rep.Add(fmt.Sprintf("Bundled assets (%d files)", assetCount), "info", "Files under assets/ were scanned for secrets and endpoints.", "assets/")
	}
	if len(urls) > 0 {
		rep.Add(fmt.Sprintf("Referenced network endpoints (%d)", len(urls)), "info", "Domains extracted - recon / attack surface leads.", "", joinSorted(urls, 15))
	}
	if len(ips) > 0 {
		rep.Add(fmt.Sprintf("Hardcoded IP addresses (%d)", len(ips)), "info", "IPs embedded in the app.", "", joinSorted(ips, 10))
	}
}

func analyzeSingleFile(path string, rep *output.Report) {
	data, err := os.ReadFile(path)
	if err != nil {
		rep.Add("Unreadable file", "info", err.Error(), path)
		return
	}
	if len(data) > maxMember {
		data = data[:maxMember]
	}
	name := filepath.Base(path)
	seen := map[seenKey]bool{}
	urls := map[string]bool{}
	ips := map[string]bool{}
	switch {
	case isDex(data):
		analyzeDex(data, name, rep, seen, urls, ips)
	case isELF(data):
		analyzeELF(data, name, rep, seen, urls, ips)
	}
	scanSecrets(textFromBytes(data), name, rep, seen)
	collectURLsIPs(data, urls, ips)
	if len(urls) > 0 {
		rep.Add(fmt.Sprintf("Referenced network endpoints (%d)", len(urls)), "info", "Domains extracted - recon / attack surface leads.", "", joinSorted(urls, 15))
	}
	if len(ips) > 0 {
		rep.Add(fmt.Sprintf("Hardcoded IP addresses (%d)", len(ips)), "info", "IPs embedded in the file.", "", joinSorted(ips, 10))
	}
}

func analyzeDirectory(root string, rep *output.Report) {
	seen := map[seenKey]bool{}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			if strings.Contains(p, ".git") || strings.Contains(p, "node_modules") || strings.Contains(p, "__pycache__") {
				return filepath.SkipDir
			}
			return nil
		}
		if archiveExt[strings.ToLower(filepath.Ext(p))] {
			analyzeArchive(p, rep)
			return nil
		}
		if fi.Size() > maxMember {
			return nil
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		scanSecrets(textFromBytes(data), rel, rep, seen)
		return nil
	})
}

func AnalyzeFileTarget(target, jsonOut, templates string) int {
	fi, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Target not found: %s\n", target)
		return 2
	}
	extraSecretPatterns = nil
	if templates != "" {
		tdir := templates
		if templates == "auto" || templates == "nuclei" {
			tdir = update.NucleiTemplatesDir()
		}
		extraSecretPatterns = loadSecretTemplates(tdir)
		if len(extraSecretPatterns) > 0 {
			fmt.Printf("[*] Loaded %d custom secret template(s)\n", len(extraSecretPatterns))
		}
	}
	rep := output.NewReport(target, "file")
	if fi.IsDir() {
		fmt.Printf("[*] Recursively analyzing directory: %s\n", target)
		analyzeDirectory(target, rep)
	} else {
		ext := strings.ToLower(filepath.Ext(target))
		fmt.Printf("[*] File: %s\n", target)
		if archiveExt[ext] || isZip(target) {
			analyzeArchive(target, rep)
		} else {
			analyzeSingleFile(target, rep)
		}
	}
	rep.Print()
	if jsonOut != "" {
		output.WriteJSON(rep, jsonOut)
	}
	return 0
}

func isZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}
	return magic[0] == 'P' && magic[1] == 'K'
}

// ===========================================================================
//  update-templates
// ===========================================================================

func joinSorted(m map[string]bool, limit int) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	return strings.Join(keys, ", ")
}

// AnalyzeFile runs the file engine and returns the report (no printing). For the SDK.
func AnalyzeFile(path string) *output.Report {
	rep := output.NewReport(path, "file")
	fi, err := os.Stat(path)
	if err != nil {
		return rep
	}
	if fi.IsDir() {
		analyzeDirectory(path, rep)
	} else {
		ext := strings.ToLower(filepath.Ext(path))
		if archiveExt[ext] || isZip(path) {
			analyzeArchive(path, rep)
		} else {
			analyzeSingleFile(path, rep)
		}
	}
	return rep
}
