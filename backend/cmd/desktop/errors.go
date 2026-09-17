package main

import "errors"

// errUnsupported is returned rather than silently doing nothing, so a UI that
// somehow reached this call gets an honest failure.
var errUnsupported = errors.New("start at login is not available in this build")
