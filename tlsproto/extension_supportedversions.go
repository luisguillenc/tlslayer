// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"

	"github.com/luisguillenc/tlslayer"
)

// SupportedVersion is like ProtocolVersion but values "0x7f00 | draft_version" are valid
type SupportedVersion uint16

// IsGREASE returns true if is a grease value
func (sv SupportedVersion) IsGREASE() bool {
	return isGREASE16(uint16(sv))
}

// IsDraft returns true if is a draft version
func (sv SupportedVersion) IsDraft() bool {
	mask := SupportedVersion(0xff00)
	r := mask & sv
	return r == SupportedVersion(0x7f00)
}

func (sv SupportedVersion) getDesc() string {
	if sv.IsDraft() {
		ver := SupportedVersion(0x00FF) & sv
		return fmt.Sprintf("TLS_1.3(draft %d)", ver)
	}
	if sv.IsGREASE() {
		return "GREASE"
	}
	switch tlslayer.ProtocolVersion(sv) {
	case tlslayer.VersionSSL30:
		return "SSL_3.0"
	case tlslayer.VersionTLS10:
		return "TLS_1.0"
	case tlslayer.VersionTLS11:
		return "TLS_1.1"
	case tlslayer.VersionTLS12:
		return "TLS_1.2"
	case tlslayer.VersionTLS13:
		return "TLS_1.3"
	default:
		return "unknown"
	}
}

func (sv SupportedVersion) String() string {
	return fmt.Sprintf("%s(%d)", sv.getDesc(), sv)
}

func decodeExtSupportedVersions(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	switch ht {
	case HandshakeTypeClientHello:
		if len(data) < 1 {
			return ErrHandshakeExtBadLength
		}
		verLen := int(data[0])
		data = data[1:]

		if len(data) < verLen {
			return ErrHandshakeExtBadLength
		}
		info.SupportedVersions = make([]SupportedVersion, verLen/2)
		for i := 0; i < verLen/2; i++ {
			info.SupportedVersions[i] = SupportedVersion(uint16(data[i*2])<<8 | uint16(data[i*2+1]))
		}
	case HandshakeTypeServerHello:
		if len(data) != 2 {
			return ErrHandshakeExtBadLength
		}
		info.SupportedVersions = make([]SupportedVersion, 0, 1)
		sup := SupportedVersion(uint16(data[0])<<8 | uint16(data[1]))
		info.SupportedVersions = append(info.SupportedVersions, sup)
	}

	return nil
}
