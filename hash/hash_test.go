package hash

import (
	"testing"
)

func TestEncrypt(t *testing.T) {
	_, err := Encrypt("a6843639-59ed-41bd-97c6-1187348e2f50")
	if err != nil {
		t.Errorf("Failed %v", err)
	}
}

func TestVerify(t *testing.T) {
	res := Verfify("boom", "$2a$04$oa1CD6lN6FQTbvWsBsjWKOCleQ8stYPoBiMQrLwMgpcSHC9W2UHNy")
	if !res {
		t.Error("Verification Failed")
	}
	res = Verfify("wrong", "$2a$04$oa1CD6lN6FQTbvWsBsjWKOCleQ8stYPoBiMQrLwMgpcSHC9W2UHNy")
	if res {
		t.Error("Should fail")
	}
}

func TestWrongPwd(t *testing.T) {
	res := Verfify("wrong", "$2a$04$oa1CD6lN6FQTbvWsBsjWKOCleQ8stYPoBiMQrLwMgpcSHC9W2UHNy")
	if res {
		t.Error("Should fail")
	}
}
