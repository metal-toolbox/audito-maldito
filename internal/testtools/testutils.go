package testtools

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Intn returns a random number between min and max.
func Intn(t *testing.T, min, max int64) int64 {
	t.Helper()

	require.Less(t, min, max, "min must be less than max")

	diff := max - min
	bigI, err := rand.Int(rand.Reader, big.NewInt(diff))
	require.NoError(t, err, "failed to generate random number")

	i := bigI.Int64()
	return i + min
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
