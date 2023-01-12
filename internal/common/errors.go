package common

type RemoteUserLoginValidateError struct {
	noEvent bool
	noPID   bool
	noCred  bool
	message string
}

func (o RemoteUserLoginValidateError) Error() string {
	return o.message
}
