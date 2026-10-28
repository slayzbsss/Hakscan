package output

import "testing"

func TestMask(t *testing.T) {
	got := Mask("AKIAIOSFODNN7EXAMPLE")
	if got == "" || got == "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("mask not applied: %q", got)
	}
}
