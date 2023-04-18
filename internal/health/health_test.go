package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/metal-toolbox/audito-maldito/internal/testtools"
)

func TestNewHealth_DefaultReadiness(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	h := NewHealth()

	assert.True(t, h.IsReady(), "health should be ready by default")

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case err := <-h.WaitForReady(ctx):
		// Success.
		assert.NoError(t, err, "wait for ready should not return an error")
	}
}

func TestHealth_WaitForReady(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()

	h := NewHealth()

	numServices := int(testtools.Intn(t, 0, 20))
	for i := 0; i < numServices; i++ {
		h.AddReadiness("test")

		assert.False(t, h.IsReady(), "health should not be ready yet")

		go h.OnReady("test")
	}

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case err := <-h.WaitForReady(ctx):
		assert.NoError(t, err, "wait for ready should not return an error")
		assert.True(t, h.IsReady(), "health should be ready now")
	}
}

func TestHealth_WaitForReadyCtxOrTimeout_Canceled(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	cancelFn()

	h := NewHealth()

	numServices := int(testtools.Intn(t, 0, 20))
	for i := 0; i < numServices; i++ {
		h.AddReadiness("test")
	}

	err := <-h.WaitForReady(ctx)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, h.IsReady(), "health should not ready")
}

func TestHealth_WaitForReadyCtxOrTimeout_TimedOut(t *testing.T) {
	t.Parallel()

	ctx, cancelFn := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelFn()

	h := NewHealth()

	numServices := int(testtools.Intn(t, 0, 20))
	for i := 0; i < numServices; i++ {
		h.AddReadiness("test")
	}

	err := <-h.WaitForReady(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, h.IsReady(), "health should not ready")
}
