package seal

import "errors"

var ErrExpired = errors.New(`seal: expired`)
var ErrDateYet = errors.New(`seal: date yet`)
var ErrDamaged = errors.New(`seal: damaged`)
var ErrNil = errors.New(`seal: chain nil`)
