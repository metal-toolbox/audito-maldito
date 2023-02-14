package common

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var timedOutErr = errors.New("timed-out")

// NewSingleReadinessHealth returns a *Health with its readiness counter
// set to one.
func NewSingleReadinessHealth() *Health {
	h := NewHealth()
	h.AddReadiness()

	return h
}

// NewHealth returns a *Health.
func NewHealth() *Health {
	return &Health{
		readyWG: &sync.WaitGroup{},
	}
}

// Health represents the application's health.
type Health struct {
	readyWG *sync.WaitGroup
}

// AddReadiness increments the readiness counter by one.
//
// Refer to WaitForReady for details on readiness functionality.
func (o *Health) AddReadiness() {
	o.readyWG.Add(1)
}

// OnReady decrements the readiness counter by one.
//
// Refer to WaitForReady for details on readiness functionality.
func (o *Health) OnReady() {
	o.readyWG.Done()
}

// WaitForReadyCtxOrTimeout is a wrapper for WaitForReady with the addition
// of monitoring a context.Context for cancellation and a timeout. nil is
// returned if the readiness counter hits zero before ctx is marked as done
// and before the timeout occurs.
//
// A non-nil error is returned if ctx is marked as done or the timeout
// occurs prior to the readiness counter hitting zero.
func (o *Health) WaitForReadyCtxOrTimeout(ctx context.Context, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(timeout):
		return fmt.Errorf("timeout of %s exceeded - %w", timeout.String(), timedOutErr)
	case <-o.WaitForReady():
		return nil
	}
}

// WaitForReady returns a channel that is closed when the readiness counter
// hits zero, signalling that all internal application services are ready.
func (o *Health) WaitForReady() <-chan struct{} {
	ready := make(chan struct{})

	go func() {
		o.readyWG.Wait()
		close(ready)
	}()

	return ready
}
