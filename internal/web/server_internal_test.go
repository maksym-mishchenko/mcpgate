package web

import (
	"strings"
	"testing"
)

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

func TestStaticPendingCardsAvoidInlineHandlers(t *testing.T) {
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read static index: %v", err)
	}
	html := string(data)
	if strings.Contains(html, "onclick=\"decide(") {
		t.Fatal("pending approval cards must not use inline onclick handlers with untrusted keys")
	}
	if !strings.Contains(html, "addEventListener('click', () => decide(key, 'allow'))") {
		t.Fatal("allow button should bind approval key through addEventListener")
	}
}
