package handler

import (
	"github.com/sir-labs/sir-auth/internal/model"
	"testing"
)

func TestPublicPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE(challenge, verifier) {
		t.Fatal("RFC 7636 vector failed")
	}
	if verifyPKCE(challenge, verifier+"x") || verifyPKCE("", "") {
		t.Fatal("accepted invalid proof")
	}
	c := &model.OAuthClient{Public: true, RedirectURI: "http://127.0.0.1/callback"}
	state := "012345678901234567890123456789012345"
	if !validPublicAuthorization(c, "http://127.0.0.1:12345/callback", challenge, "S256", state) {
		t.Fatal("valid loopback rejected")
	}
	for _, uri := range []string{"https://evil.test/callback", "http://localhost:1234/callback", "http://127.0.0.1:1234/wrong", "http://127.0.0.1:1234/callback?next=evil", "http://user@127.0.0.1:1234/callback"} {
		if validPublicAuthorization(c, uri, challenge, "S256", state) {
			t.Fatalf("accepted %s", uri)
		}
	}
	if validPublicAuthorization(c, "http://127.0.0.1:1234/callback", challenge, "plain", state) {
		t.Fatal("plain accepted")
	}
	if validPublicAuthorization(c, "http://127.0.0.1:1234/callback", challenge, "S256", "") {
		t.Fatal("missing state accepted")
	}
}
