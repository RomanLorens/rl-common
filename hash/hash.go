package hash

import (
	"golang.org/x/crypto/bcrypt"
)

//Verify checks if str matches hash
func Verfify(s string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(s))
	return err == nil
}

//Encrypt encrypts string
func Encrypt(s string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(s), 4)
	return string(bytes), err
}
