package auth

import "testing"

func TestDocumentTokenEnvironmentBoundary(t *testing.T) {
	for _, tc := range []struct {
		subject, tenant, env, client string
		allowed                      bool
	}{
		{"actor", "tenant-a", "sandbox", "app", true},
		{"actor", "tenant-a", "production", "app", false},
		{"actor", "tenant-a", "", "app", false},
		{"service", "", "", "internal", true},
		{"service", "", "production", "internal", false},
		{"", "tenant-a", "sandbox", "app", false},
		{"actor", "", "sandbox", "", false},
	} {
		if err := validateContext(tc.subject, tc.tenant, tc.env, tc.client, "sandbox"); (err == nil) != tc.allowed {
			t.Fatal(tc, err)
		}
	}
}

func TestInternalPrivilegeRequiresExplicitClientAndNoTenantIdentity(t *testing.T) {
	allowed := map[string]bool{"reviewed-service": true}
	for _, tc := range []struct {
		tenant, application, client string
		want                        bool
	}{
		{"", "", "reviewed-service", true},
		{"", "", "unknown", false},
		{"tenant", "", "reviewed-service", false},
		{"", "tenant-application", "reviewed-service", false},
		{"", "", "", false},
	} {
		if got := trustedInternal(tc.tenant, tc.application, tc.client, allowed); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	if trustedInternal("", "", "reviewed-service", nil) {
		t.Fatal("empty policy allowed internal access")
	}
}
