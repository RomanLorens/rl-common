package filter

import (
	"net/http/httptest"
	"testing"
)

func TestWhitelistedEndpoint(t *testing.T) {
	f := NewWhiteListedEndpointFilter([]string{"/api/1"})
	r := httptest.NewRequest("GET", "http://192.0.2.1/api/1", nil)
	ok, r := f.DoFilter(r)

	if !ok {
		t.Errorf("Should pass - %v", ok)
	}
}

func TestProtectedEndpoint(t *testing.T) {
	f := NewWhiteListedEndpointFilter([]string{"/api/1"})
	r := httptest.NewRequest("GET", "http://192.0.2.1/api/333", nil)
	ok, r := f.DoFilter(r)

	if ok {
		t.Errorf("Should fail - %v", ok)
	}
}
