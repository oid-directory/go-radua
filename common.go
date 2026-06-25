package radua

import (
	"errors"
)

var (
	mkerr func(string) error = errors.New
)
