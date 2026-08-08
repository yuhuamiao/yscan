package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccessPolicyRequiresCIDRForNonLoopbackAndFiltersRequests(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", ":8080", "[::]:8080", "192.0.2.10:8080"} {
		if err := (AccessPolicy{}).Validate(address); err == nil {
			t.Fatalf("non-loopback listener %q without CIDR must fail", address)
		}
	}
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if err := (AccessPolicy{}).Validate(address); err != nil {
			t.Fatalf("loopback listener %q: %v", address, err)
		}
	}
	policy := AccessPolicy{TrustedCIDRs: []string{"10.0.0.0/8"}}
	if err := policy.Validate("0.0.0.0:8080"); err != nil {
		t.Fatalf("allowlisted listener: %v", err)
	}
	if err := (AccessPolicy{TrustedCIDRs: []string{"invalid"}}).Validate("127.0.0.1:8080"); err == nil {
		t.Fatal("invalid CIDR must be rejected even for a loopback listener")
	}
	handler := policy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	allowed := httptest.NewRequest(http.MethodGet, "/", nil)
	allowed.RemoteAddr = "10.1.2.3:1234"
	allowedResult := httptest.NewRecorder()
	handler.ServeHTTP(allowedResult, allowed)
	if allowedResult.Code != http.StatusNoContent {
		t.Fatalf("allowed status=%d", allowedResult.Code)
	}
	denied := httptest.NewRequest(http.MethodGet, "/", nil)
	denied.RemoteAddr = "192.0.2.1:1234"
	deniedResult := httptest.NewRecorder()
	handler.ServeHTTP(deniedResult, denied)
	if deniedResult.Code != http.StatusForbidden {
		t.Fatalf("denied status=%d", deniedResult.Code)
	}
}
