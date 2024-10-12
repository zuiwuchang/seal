package frame

import "errors"

var ErrIdBitsInvalid = errors.New(`id bits invalid`)
var ErrPayloadBitsInvalid = errors.New(`payload bits invalid`)
var ErrFrameWriterExpired = errors.New(`frame writer expired`)
var ErrFramePayloadLengthInvalid = errors.New(`frame payload length invalid`)
