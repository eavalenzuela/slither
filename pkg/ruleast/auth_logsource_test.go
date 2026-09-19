package ruleast

import (
	"strings"
	"testing"
)

const authRuleBody = `
detection:
  sel:
    Service: sshd
    Status: Failure
  condition: sel
`

func TestLogSourceAuthenticationCategory(t *testing.T) {
	src := "title: t\nid: 11111111-1111-4111-8111-111111111111\nlevel: low\nlogsource:\n  product: linux\n  category: authentication\n" + authRuleBody
	art, _, _, err := Compile([]byte(src))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if art.Rule.Category != CategoryAuthentication {
		t.Errorf("category = %q", art.Rule.Category)
	}
}

// TestLogSourceServiceAuthWithoutCategory — the spelling public Sigma
// packs use for Linux auth rules (`service: auth`, no category) must
// compile to the same category so those rules import unchanged.
func TestLogSourceServiceAuthWithoutCategory(t *testing.T) {
	for _, svc := range []string{"auth", "sshd", "sudo", "PAM"} {
		src := "title: t\nid: 11111111-1111-4111-8111-111111111111\nlevel: low\nlogsource:\n  product: linux\n  service: " + svc + "\n" + authRuleBody
		art, _, _, err := Compile([]byte(src))
		if err != nil {
			t.Fatalf("service %s: Compile: %v", svc, err)
		}
		if art.Rule.Category != CategoryAuthentication {
			t.Errorf("service %s: category = %q", svc, art.Rule.Category)
		}
	}
}

func TestLogSourceUnknownServiceStillRejected(t *testing.T) {
	src := "title: t\nid: 11111111-1111-4111-8111-111111111111\nlevel: low\nlogsource:\n  product: linux\n  service: cron\n" + authRuleBody
	_, _, _, err := Compile([]byte(src))
	if err == nil {
		t.Fatal("service: cron with no category should not compile")
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Errorf("error should list the accepted categories: %v", err)
	}
}
