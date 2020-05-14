// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlslayer

import (
	"errors"
)

// Some well knwon errors
var (
	ErrTLSWrongContentType     = errors.New("tls record is of wrong type")
	ErrTLSWrongProtocolVersion = errors.New("tls record is of unknown version")
	ErrTLSWrongSize            = errors.New("tls record is of wrong size")
	ErrTLSWrongPayload         = errors.New("tls record payload size doesn't match with record size")
	ErrTLSPayloadEmpty         = errors.New("tls record payload is empty")
)
