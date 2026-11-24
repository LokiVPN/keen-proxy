package model

// AppliedUnsavedError reports a successful runtime change whose configuration
// could not be persisted. The saved configuration may be used on restart.
type AppliedUnsavedError struct {
	Err error
}

func (e *AppliedUnsavedError) Error() string {
	return "configuration applied but not saved: " + e.Err.Error()
}

func (e *AppliedUnsavedError) Unwrap() error { return e.Err }
