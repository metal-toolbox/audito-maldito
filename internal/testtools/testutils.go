package testtools

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// Intn returns a random number between min and max.
// TODO(jaosorior): This is innefficient, refactor later.
func Intn(t *testing.T, min, max int64) int64 {
	t.Helper()

retry:
	bigI, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		t.Fatal(err)
	}

	i := bigI.Int64()

	if i < min {
		goto retry
	}

	return i
}

func RandomBytes(t *testing.T, min, max int64) []byte {
	t.Helper()

	numBytes := Intn(t, min, max)

	if numBytes == 0 {
		return nil
	}

	b := make([]byte, numBytes)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatal(err)
	}

	return b
}
