package common

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewGenericSyncMap(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	assert.NotNil(t, m)

	assert.NotNil(t, m.m)
}

func TestNewGenericSyncMap_Load_KeyExists(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	result, exists := m.Load(k)
	assert.True(t, exists)

	assert.Equal(t, v, result)
}

func TestNewGenericSyncMap_Load_KeyDoesNotExist(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	_, exists := m.Load(0x8badf00d)
	assert.False(t, exists)
}

func TestNewGenericSyncMap_Has_KeyExists(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	exists := m.Has(k)
	assert.True(t, exists)
}

func TestNewGenericSyncMap_Has_KeyDoesNotExist(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	exists := m.Has(0x8badf00d)
	assert.False(t, exists)
}

func TestNewGenericSyncMap_Store(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	result, exists := m.Load(k)
	assert.True(t, exists)

	assert.Equal(t, v, result)
}

func TestNewGenericSyncMap_Delete(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	m.Delete(k)

	_, exists := m.Load(0x8badf00d)
	assert.False(t, exists)
}

func TestNewGenericSyncMap_DeleteUnsafe(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	m.DeleteUnsafe(k)

	_, exists := m.Load(0x8badf00d)
	assert.False(t, exists)
}

func TestNewGenericSyncMap_Len(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	m.Store(0, RemoteUserLogin{
		PID: 0,
	})
	m.Store(1, RemoteUserLogin{
		PID: 1,
	})
	m.Store(2, RemoteUserLogin{
		PID: 2,
	})
	m.Store(3, RemoteUserLogin{
		PID: 3,
	})

	assert.Equal(t, 4, m.Len())
}

func TestNewGenericSyncMap_Iterate_AllEntries(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	m.Store(0, RemoteUserLogin{
		PID: 0,
	})
	m.Store(1, RemoteUserLogin{
		PID: 1,
	})
	m.Store(2, RemoteUserLogin{
		PID: 2,
	})
	m.Store(3, RemoteUserLogin{
		PID: 3,
	})

	i := 0
	m.Iterate(func(key int, value RemoteUserLogin) bool {
		i++
		return true
	})

	assert.Equal(t, i, m.Len())
}

func TestNewGenericSyncMap_Iterate_OnlyOneEntry(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	m.Store(0, RemoteUserLogin{
		PID: 0,
	})
	m.Store(1, RemoteUserLogin{
		PID: 1,
	})
	m.Store(2, RemoteUserLogin{
		PID: 2,
	})
	m.Store(3, RemoteUserLogin{
		PID: 3,
	})

	i := 0
	m.Iterate(func(key int, value RemoteUserLogin) bool {
		i++
		return false
	})

	assert.Equal(t, i, 1)
}

func TestNewGenericSyncMap_WithLockedValueDo_KeyExists(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	called := false
	err := m.WithLockedValueDo(k, func(value RemoteUserLogin) error {
		assert.Equal(t, v, value)
		called = true
		return nil
	})

	assert.Nil(t, err)
	assert.True(t, called)
}

func TestNewGenericSyncMap_WithLockedValueDo_KeyDoesNotExist(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	called := false
	err := m.WithLockedValueDo(666, func(value RemoteUserLogin) error {
		called = true
		return nil
	})

	assert.Nil(t, err)
	assert.False(t, called)
}

func TestNewGenericSyncMap_WithLockedValueDo_NilError(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	called := false
	err := m.WithLockedValueDo(k, func(value RemoteUserLogin) error {
		called = true
		return nil
	})

	assert.Nil(t, err)
	assert.True(t, called)
}

func TestNewGenericSyncMap_WithLockedValueDo_NonNilError(t *testing.T) {
	t.Parallel()

	m := NewGenericSyncMap[int, RemoteUserLogin]()

	k := 0xdeadbeef
	v := RemoteUserLogin{
		PID: k,
	}

	m.Store(k, v)

	exp := errors.New("blam")
	err := m.WithLockedValueDo(k, func(value RemoteUserLogin) error {
		return exp
	})

	assert.ErrorIs(t, err, exp)
}
