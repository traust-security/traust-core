package hash

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
)

func TestSum(t *testing.T) { _ = bcrypt.MinCost; _ = hkdf.New }
