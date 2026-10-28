package main

import "testing"

func TestMask(t *testing.T) {
	got := mask("AKIAIOSFODNN7EXAMPLE")
	if got == "" || got == "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("mask not applied: %q", got)
	}
}

func TestMatchWords(t *testing.T) {
	if !matchWords("hello world", []string{"world"}, false) {
		t.Fatal("any match should succeed")
	}
	if matchWords("hello", []string{"a", "b"}, true) {
		t.Fatal("all match should fail")
	}
	if !matchWords("ab", []string{"a", "b"}, true) {
		t.Fatal("all match should pass")
	}
}

func TestReduce(t *testing.T) {
	if !reduce([]bool{true, true}, true) {
		t.Fatal("and of all-true should be true")
	}
	if reduce([]bool{true, false}, true) {
		t.Fatal("and with a false should be false")
	}
	if !reduce([]bool{false, true}, false) {
		t.Fatal("or with a true should be true")
	}
}

func TestContainsInt(t *testing.T) {
	if !containsInt([]int{200, 404}, 200) {
		t.Fatal("200 should be found")
	}
	if containsInt([]int{200}, 500) {
		t.Fatal("500 should not be found")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("abcdef", 3) != "abc" {
		t.Fatal("truncate failed")
	}
	if truncate("ab", 5) != "ab" {
		t.Fatal("short string should be unchanged")
	}
}

func TestJoinURL(t *testing.T) {
	if got := joinURL("https://x.com/a/b", "/c"); got != "https://x.com/c" {
		t.Fatalf("joinURL: got %s", got)
	}
}

func TestParseAXMLInvalid(t *testing.T) {
	if _, err := parseAXML([]byte("not an axml file")); err == nil {
		t.Fatal("expected an error on invalid AXML")
	}
}

func TestScanSecrets(t *testing.T) {
	rep := newReport("t", "file")
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
