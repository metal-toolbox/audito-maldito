package common

import (
	"context"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

func TestNewHealth_DefaultReadiness(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	h := NewHealth()

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-h.WaitForReady():
		// Success.
	}
}

func TestHealth_WaitForReady(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	h := NewHealth()

	numServices := int(intn(t, 0, 20))
	for i := 0; i < numServices; i++ {
		h.AddReadiness()
		go h.OnReady()
	}

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-h.WaitForReady():
		// Success.
	}
}

func TestHealth_WaitForReadyCtxOrTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	h := NewHealth()

	numServices := int(intn(t, 0, 20))
	for i := 0; i < numServices; i++ {
		h.AddReadiness()
		go h.OnReady()
	}

	err := h.WaitForReadyCtxOrTimeout(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHealth_WaitForReadyCtxOrTimeout_Canceled(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	cancelFn()

	h := NewHealth()

	numServices := int(intn(t, 0, 20))
	for i := 0; i < numServices; i++ {
		h.AddReadiness()
	}

	err := h.WaitForReadyCtxOrTimeout(ctx, time.Second)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestHealth_WaitForReadyCtxOrTimeout_TimedOut(t *testing.T) {
	t.Parallel()

	h := NewHealth()

	numServices := int(intn(t, 0, 20))
	for i := 0; i < numServices; i++ {
		h.AddReadiness()
	}

	err := h.WaitForReadyCtxOrTimeout(context.Background(), time.Nanosecond)
	assert.ErrorIs(t, err, timedOutErr)
}

// intn returns a random number between min and max.
func intn(t *testing.T, min, max int64) int64 {
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
