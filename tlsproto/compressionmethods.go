// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import "fmt"

// CompressionMethod defines the type of compression of an ssl conversation
type CompressionMethod uint16

// CompressionMethod possible values
const (
	CompressionMethodNull    CompressionMethod = 0
	CompressionMethodDeflate CompressionMethod = 1
)

func (c CompressionMethod) getDesc() string {
	switch c {
	case CompressionMethodNull:
		return "null"
	case CompressionMethodDeflate:
		return "DEFLATE"
	default:
		return "unknown"
	}
}

// String method to return string of ContentType
func (c CompressionMethod) String() string {
	return fmt.Sprintf("%s(%d)", c.getDesc(), c)
}

// IsValid returns true if is a valid value
func (c CompressionMethod) IsValid() bool {
	return (c == CompressionMethodNull) || (c == CompressionMethodDeflate)
}
