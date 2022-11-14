package common

type remoteUserLoginValidateError struct {
	noEvent bool
	noPID   bool
	noCred  bool
	message string
}

func (o remoteUserLoginValidateError) Error() string {
	return o.message
}
