package common

import (
	"errors"
	"testing"

	"github.com/metal-toolbox/auditevent"
	"github.com/stretchr/testify/assert"
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
	if !errors.As(err, &exp) {
		t.Fatalf("expected %T - got %T", exp, err)
	}

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
	if !errors.As(err, &exp) {
		t.Fatalf("expected %T - got %T", exp, err)
	}

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
	if !errors.As(err, &exp) {
		t.Fatalf("expected %T - got %T", exp, err)
	}

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
	if !errors.As(err, &exp) {
		t.Fatalf("expected %T - got %T", exp, err)
	}

	assert.True(t, exp.noCred)
}
