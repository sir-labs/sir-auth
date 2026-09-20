package handler

import (
	"strings"
	"testing"
)

func TestMCPInstallEscapesToken(t *testing.T) {
	malicious := `"><script>alert('token')</script>`
	page := mcpInstallHTML(malicious)
	if strings.Contains(page, malicious) || !strings.Contains(page, `value="`+htmlEscape(malicious)+`"`) {
		t.Fatal("token must be escaped in the input attribute")
	}
	if strings.Contains(page, "%!") {
		t.Fatal("invalid HTML format arguments")
	}
}

func TestMCPInstallStartsWithoutStoredToken(t *testing.T) {
	page := mcpInstallHTML("")
	if !strings.Contains(page, `type="password" value=""`) {
		t.Fatal("existing-token setup must start with an empty token field")
	}
	if strings.Count(page, " disabled>") != 2 {
		t.Fatal("both install buttons must start disabled until JavaScript validates the token")
	}
}
