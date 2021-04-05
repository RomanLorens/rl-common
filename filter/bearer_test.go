package filter

import (
	"net/http/httptest"
	"testing"

	"github.com/RomanLorens/logger/log"
)

func TestBearer(t *testing.T) {
	l := log.PrintLogger()
	cfg := []WhiteList{{User: "user1", Token: "$2a$04$h84Yk8/pjkdOn/Gxv9CrIeVv8MA/m9qhQhW1BIE0sGhIiTWi45/Xu", IsAdmin: true}}
	f := NewBearerTokenIPFilter(l, cfg)
	r := httptest.NewRequest("GET", "http://192.0.2.1/test", nil)
	r.Header.Add("Authorization", "Bearer user1-a6843639-59ed-41bd-97c6-1187348e2f50")

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
