package web

import "testing"

func TestTokenMatches(t *testing.T) {
	if !tokenMatches("test-secret-token", "test-secret-token") {
		t.Fatal("matching tokens should authenticate")
	}
	if tokenMatches("wrong-secret-token", "test-secret-token") {
		t.Fatal("different same-length tokens should not authenticate")
	}
	if tokenMatches("short", "test-secret-token") {
		t.Fatal("different length tokens should not authenticate")
	}
}
