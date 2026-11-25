package model

import "errors"

// ErrConnectionTagConflict indicates that compiled outbounds or endpoints
// would claim the same tag, including tags generated for routing.
var ErrConnectionTagConflict = errors.New("connection identifier conflicts with a routing tag")

// ErrConnectionRoutingOverride indicates that a wizard import references a
// tag or assigns host routing that the application owns.
var ErrConnectionRoutingOverride = errors.New("profile includes unsupported routing options")

// AppliedUnsavedError reports a successful runtime change whose configuration
// could not be persisted. The saved configuration may be used on restart.
type AppliedUnsavedError struct {
	Err error
}

func (e *AppliedUnsavedError) Error() string {
	return "configuration applied but not saved: " + e.Err.Error()
}

func (e *AppliedUnsavedError) Unwrap() error { return e.Err }
