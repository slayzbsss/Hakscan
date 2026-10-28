package web

import "testing"

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
