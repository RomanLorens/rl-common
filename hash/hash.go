package hash

import (
	"golang.org/x/crypto/bcrypt"
)

//Verify checks if bearer matches hash
func Verfify(bearer string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(bearer))
	return err == nil
}

//Encrypt encrypts bearer
func Encrypt(bearer string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(bearer), 4)
	return string(bytes), err
}
