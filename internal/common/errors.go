package common

type RemoteUserLoginValidateError struct {
	noEvent bool
	badPID  bool
	noCred  bool
	message string
}

func (o RemoteUserLoginValidateError) Error() string {
	return o.message
}
