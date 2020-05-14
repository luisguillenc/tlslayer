// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlslayer

import "fmt"

// ContentType defines the type of content of an SSL record
type ContentType uint8

// ContentType possible values
const (
	ContentTypeChangeCipherSpec ContentType = 20
	ContentTypeAlert            ContentType = 21
	ContentTypeHandshake        ContentType = 22
	ContentTypeApplicationData  ContentType = 23
)

// getDesc resturns description of a content type
func (c ContentType) getDesc() string {
	switch c {
	case ContentTypeChangeCipherSpec:
		return "change_cipher_spec"
	case ContentTypeAlert:
		return "alert"
	case ContentTypeHandshake:
		return "handshake"
	case ContentTypeApplicationData:
		return "application_data"
	default:
		return "unknown"
	}
}

// String method to return string of ContentType
func (c ContentType) String() string {
	return fmt.Sprintf("%s(%d)", c.getDesc(), c)
}

// IsValid method checks if it's a valid value
func (c ContentType) IsValid() bool {
	if c >= 20 && c <= 23 {
		return true
	}
	return false
}
