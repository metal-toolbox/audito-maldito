package common

import "sync"

// GenericSyncMap is a generic sync.Map.
type GenericSyncMap[K comparable, V any] struct {
	// Map is the underlying map.
	m   map[K]V
	mtx sync.Mutex
}

// NewGenericSyncMap returns a new GenericSyncMap.
func NewGenericSyncMap[K comparable, V any]() *GenericSyncMap[K, V] {
	return &GenericSyncMap[K, V]{
		m: make(map[K]V),
	}
}

// Load returns the value stored in the map for a key, or nil if no
// value is present. The ok result indicates whether value was found
// in the map.
func (m *GenericSyncMap[K, V]) Load(key K) (V, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	value, ok := m.m[key]
	return value, ok
}

// Store sets the value for a key.
func (m *GenericSyncMap[K, V]) Store(key K, value V) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.m[key] = value
}

// Delete deletes the value for a key.
func (m *GenericSyncMap[K, V]) Delete(key K) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.DeleteUnsafe(key)
}

// DeleteUnsafe deletes the value for a key without locking.
func (m *GenericSyncMap[K, V]) DeleteUnsafe(key K) {
	delete(m.m, key)
}

// Len returns the number of items in the map.
func (m *GenericSyncMap[K, V]) Len() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	return len(m.m)
}

// Iterate iterates over the map and calls the callback for each key/value
// pair. If the callback returns false, the iteration stops.
// Note that the callback is called while the map is locked, so it should
// not call any methods on the map.
func (m *GenericSyncMap[K, V]) Iterate(cb func(key K, value V) bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	for k, v := range m.m {
		if !cb(k, v) {
			break
		}
	}
}
