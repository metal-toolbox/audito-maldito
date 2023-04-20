package common

import (
	"testing"

	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteUserLogin_Validate(t *testing.T) {
	t.Parallel()

	rul := RemoteUserLogin{
		Source:     &auditevent.AuditEvent{},
		PID:        666,
		CredUserID: "foo",
	}

	err := rul.Validate()

	assert.Nil(t, err)
}

func TestRemoteUserLogin_Validate_SourceIsNil(t *testing.T) {
	t.Parallel()

	rul := RemoteUserLogin{
		Source:     nil,
		PID:        666,
		CredUserID: "foo",
	}

	err := rul.Validate()
	var exp *RemoteUserLoginValidateError
	require.ErrorAs(t, err, &exp)

	assert.True(t, exp.noEvent)
}

func TestRemoteUserLogin_Validate_ZeroPID(t *testing.T) {
	t.Parallel()

	rul := RemoteUserLogin{
		Source:     &auditevent.AuditEvent{},
		PID:        0,
		CredUserID: "foo",
	}

	err := rul.Validate()
	var exp *RemoteUserLoginValidateError
	require.ErrorAs(t, err, &exp)

	assert.True(t, exp.badPID)
}

func TestRemoteUserLogin_Validate_NegativePID(t *testing.T) {
	t.Parallel()

	rul := RemoteUserLogin{
		Source:     &auditevent.AuditEvent{},
		PID:        -666,
		CredUserID: "foo",
	}

	err := rul.Validate()
	var exp *RemoteUserLoginValidateError
	require.ErrorAs(t, err, &exp)

	assert.True(t, exp.badPID)
}

func TestRemoteUserLogin_Validate_EmptyCredUserID(t *testing.T) {
	t.Parallel()

	rul := RemoteUserLogin{
		Source:     &auditevent.AuditEvent{},
		PID:        666,
		CredUserID: "",
	}

	err := rul.Validate()
	var exp *RemoteUserLoginValidateError
	require.ErrorAs(t, err, &exp)

	assert.True(t, exp.noCred)
}
