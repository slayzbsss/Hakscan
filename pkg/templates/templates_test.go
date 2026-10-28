package templates

import "testing"

func TestMatchWords(t *testing.T) {
	if !MatchWords("hello world", []string{"world"}, false) {
		t.Fatal("any match should succeed")
	}
	if MatchWords("hello", []string{"a", "b"}, true) {
		t.Fatal("all match should fail")
	}
	if !MatchWords("ab", []string{"a", "b"}, true) {
		t.Fatal("all match should pass")
	}
}

func TestReduce(t *testing.T) {
	if !Reduce([]bool{true, true}, true) {
		t.Fatal("and of all-true should be true")
	}
	if Reduce([]bool{true, false}, true) {
		t.Fatal("and with a false should be false")
	}
	if !Reduce([]bool{false, true}, false) {
		t.Fatal("or with a true should be true")
	}
}

func TestContainsInt(t *testing.T) {
	if !ContainsInt([]int{200, 404}, 200) {
		t.Fatal("200 should be found")
	}
	if ContainsInt([]int{200}, 500) {
		t.Fatal("500 should not be found")
	}
}
