package filter

import (
	"net/http/httptest"
	"testing"

	"github.com/RomanLorens/logger/log"
)

func TestBearer(t *testing.T) {
	l := log.PrintLogger()
	cfg := []WhiteList{{User: "user1", Token: "$2a$04$oa1CD6lN6FQTbvWsBsjWKOCleQ8stYPoBiMQrLwMgpcSHC9W2UHNy", IsAdmin: true}}
	f := NewBearerTokenIPFilter(l, cfg)
	r := httptest.NewRequest("GET", "http://192.0.2.1/test", nil)
	r.Header.Add("Authorization", "Bearer user1-boom")

	ok, r := f.DoFilter(r)
	if !ok {
		t.Errorf("Failed %v", ok)
	}
}

func TestInvalidBearer(t *testing.T) {
	l := log.PrintLogger()
	cfg := []WhiteList{{User: "user1", Token: "$2a$04$oa1CD6lN6FQTbvWsBsjWKOCleQ8stYPoBiMQrLwMgpcSHC9W2UHNy", IsAdmin: true}}
	f := NewBearerTokenIPFilter(l, cfg)
	r := httptest.NewRequest("GET", "http://192.0.2.1/test", nil)
	r.Header.Add("Authorization", "Bearer user1-invalid")

	ok, r := f.DoFilter(r)
	if ok {
		t.Errorf("Should fail %v", ok)
	}
}

func TestIP(t *testing.T) {
	l := log.PrintLogger()
	cfg := []WhiteList{{User: "user1", IP: "192.0.2.1", IsAdmin: true}}
	f := NewBearerTokenIPFilter(l, cfg)
	r := httptest.NewRequest("GET", "http://192.0.2.1/test", nil)

	ok, r := f.DoFilter(r)
	if !ok {
		t.Errorf("Failed %v", ok)
	}
}

func TestNotAdminIP(t *testing.T) {
	l := log.PrintLogger()
	cfg := []WhiteList{{User: "user1", IP: "192.0.2.1", IsAdmin: false, Endpoints: []string{"/test"}}}
	f := NewBearerTokenIPFilter(l, cfg)
	r := httptest.NewRequest("GET", "http://192.0.2.1/test", nil)

	ok, r := f.DoFilter(r)
	if !ok {
		t.Errorf("Failed %v", ok)
	}
}
