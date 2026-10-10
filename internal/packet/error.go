package packet

import "errors"

var ErrInvalidVersion = errors.New("invalid packet version")
var ErrShortPacket = errors.New("packet too short")
var ErrInvalidLength = errors.New("invalid packet length")
