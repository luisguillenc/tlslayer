// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlslayer

import "fmt"

// ProtocolVersion of tls record and handshake
type ProtocolVersion uint16

// Version tls version possible values
const (
	VersionSSL30 ProtocolVersion = 0x300
	VersionTLS10 ProtocolVersion = 0x301
	VersionTLS11 ProtocolVersion = 0x302
	VersionTLS12 ProtocolVersion = 0x303
	VersionTLS13 ProtocolVersion = 0x304
)

func (v ProtocolVersion) getDesc() string {
	switch v {
	case VersionSSL30:
		return "SSL_3.0"
	case VersionTLS10:
		return "TLS_1.0"
	case VersionTLS11:
		return "TLS_1.1"
	case VersionTLS12:
		return "TLS_1.2"
	case VersionTLS13:
		return "TLS_1.3"
	default:
		return "unknown"
	}
}

// String method to return string of TLS version
func (v ProtocolVersion) String() string {
	return fmt.Sprintf("%s(%d)", v.getDesc(), v)
}

// IsValid method checks if it's a valid value
func (v ProtocolVersion) IsValid() bool {
	if v >= 768 && v <= 772 {
		return true
	}
	return false
}
