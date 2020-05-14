// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

const (
	// ExtSNITypeDNS SNI name type DNS
	ExtSNITypeDNS uint8 = 0
)

func decodeExtServerName(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	if len(data) == 0 {
		// empty
		return nil
	}

	if len(data) < 2 {
		return ErrHandshakeExtBadLength
	}
	sniLen := int(data[0])<<8 | int(data[0])

	data = data[2:]

	if len(data) < sniLen {
		// Malformed SNI data
		return ErrHandshakeExtBadLength
	}

	for len(data) > 0 {
		nameType := data[0]

		if len(data) < 3 {
			// Malformed ServerName
			return ErrHandshakeExtBadLength
		}

		nameLen := int(data[1])<<8 | int(data[2])

		data = data[3:]

		switch nameType {
		case ExtSNITypeDNS:
			info.SNI = string(data)
		default:
			// Unknown Name Type
		}
		data = data[nameLen:]
	}

	return nil
}
