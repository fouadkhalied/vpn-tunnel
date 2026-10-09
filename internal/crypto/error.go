package crypto

import "errors"

var ErrNotImplemented = errors.New("not implemented")
var ErrReplay = errors.New("replayed or too-old packet")
var ErrRekeyRequired = errors.New("session must be rekeyed")
var ErrInvalidPacket = errors.New("invalid encrypted packet")
