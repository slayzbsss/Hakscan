package file

import (
	"encoding/binary"
	"testing"

	"github.com/slayzbsss/Hakscan/pkg/output"
)

func TestParseAXMLInvalid(t *testing.T) {
	if _, err := parseAXML([]byte("not an axml file")); err == nil {
		t.Fatal("expected an error on invalid AXML")
	}
}

func TestScanSecrets(t *testing.T) {
	rep := output.NewReport("t", "file")
	scanSecrets(`key="AKIAIOSFODNN7EXAMPLE"`, "f", rep, map[seenKey]bool{})
	found := false
	for _, f := range rep.Findings {
		if f.Title == "Potential secret: AWS Access Key ID" {
			found = true
		}
	}
	if !found {
		t.Fatal("AWS access key not detected")
	}
}

func FuzzParseAXML(f *testing.F) {
	f.Add([]byte{0x03, 0x00, 0x08, 0x00})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseAXML(data) // must never panic
	})
}

func TestDexStrings(t *testing.T) {
	hdr := make([]byte, 0x70)
	copy(hdr, []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(hdr[0x38:], 2)
	binary.LittleEndian.PutUint32(hdr[0x3C:], 0x70)
	ids := make([]byte, 8)
	dataOff := 0x70 + 8
	var blob []byte
	put := func(s string) uint32 {
		off := uint32(dataOff + len(blob))
		blob = append(blob, byte(len(s)))
		blob = append(blob, s...)
		blob = append(blob, 0)
		return off
	}
	o1 := put("hello")
	o2 := put("https://evil.example.com")
	binary.LittleEndian.PutUint32(ids[0:], o1)
	binary.LittleEndian.PutUint32(ids[4:], o2)
	dex := append(append(hdr, ids...), blob...)

	got := dexStrings(dex)
	if len(got) != 2 || got[0] != "hello" || got[1] != "https://evil.example.com" {
		t.Fatalf("dexStrings = %q", got)
	}
	if isDex([]byte("not a dex")) {
		t.Fatal("isDex false positive")
	}
	if !isELF([]byte("\x7fELFxyz")) {
		t.Fatal("isELF should match ELF magic")
	}
}
