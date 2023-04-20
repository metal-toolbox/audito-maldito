package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/metal-toolbox/audito-maldito/internal/common"
)

const (
	// OverallReady is the key for the overall readiness status.
	OverallReady = "overall"
	// ComponentReady is the value indicating that a component is ready.
	ComponentReady = "ok"
	// ComponentNotReady is the value indicating that a component is not ready.
	ComponentNotReady = "not-ready"
)

// DefaultReadyCheckInterval is the interval for which the `WaitOnReady` function will wait.
var DefaultReadyCheckInterval = 500 * time.Millisecond

// NewHealth returns a *Health.
func NewHealth() *Health {
	return &Health{
		readyMap: common.NewGenericSyncMap[string, bool](),
	}
}

// Health represents the application's health.
type Health struct {
	readyMap *common.GenericSyncMap[string, bool]
}

// NewSingleReadinessHealth returns a *Health with its readiness counter
// set to one.
func NewSingleReadinessHealth(component string) *Health {
	h := NewHealth()
	h.AddReadiness(component)

	return h
}

// AddReadiness adds another item for the readiness system to wait for.
// This should be called once per internal application service.
// Ensure that OnReady is called for each call to AddReadiness.
func (o *Health) AddReadiness(component string) {
	o.readyMap.Store(component, false)
}

// OnReady marks an item as ready.
// This should be called once per internal application service.
// Ensure that AddReadiness is called for each call to OnReady,
// else, the readiness check will not take that component into account.
func (o *Health) OnReady(component string) {
	o.readyMap.Store(component, true)
}

// WaitForReady returns a channel that is closed when the readiness counter
// hits zero, signalling that all internal application services are ready.
func (o *Health) WaitForReady(ctx context.Context) <-chan error {
	out := make(chan error)

	go func() {
		ticker := time.NewTicker(DefaultReadyCheckInterval)
		for {
			select {
			case <-ctx.Done():
				out <- ctx.Err()
				return
			case <-ticker.C:
				if o.IsReady() {
					close(out)
					return
				}
			}
		}
	}()

	return out
}

// IsReady returns true if the readiness counter is less than or equal to.
func (o *Health) IsReady() bool {
	isReady := true
	o.readyMap.Iterate(func(key string, value bool) bool {
		if !value {
			isReady = false
			return false
		}

		return true
	})

	return isReady
}

func (o *Health) GetReadyzStatusMap() map[string]string {
	smap := make(map[string]string, o.readyMap.Len()+1)
	overalReady := true

	o.readyMap.Iterate(func(key string, value bool) bool {
		var status string
		if !value {
			overalReady = false
			status = ComponentNotReady
		} else {
			status = ComponentReady
		}

		smap[key] = status
		return true
	})

	if overalReady {
		smap[OverallReady] = ComponentReady
	} else {
		smap[OverallReady] = ComponentNotReady
	}

	return smap
}

func (o *Health) readyzHandler(w http.ResponseWriter, _ *http.Request) {
	status := o.GetReadyzStatusMap()

	// We don't use `o.IsReady()` here. We don't want to iterate
	// over the map again.
	if status[OverallReady] == ComponentReady {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_ = json.NewEncoder(w).Encode(status)
}

func (o *Health) ReadyzHandler() http.Handler {
	return http.HandlerFunc(o.readyzHandler)
}
