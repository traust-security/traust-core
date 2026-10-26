package hash

import "golang.org/x/crypto/bcrypt"

func Sum(s string) string {
	b, _ := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	return string(b)
}
