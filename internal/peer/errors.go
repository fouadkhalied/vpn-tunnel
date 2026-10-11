package peer

import "errors"

var ErrNoSession = errors.New("peer has no session")
var ErrNoEndpoint = errors.New("peer has no endpoint")
