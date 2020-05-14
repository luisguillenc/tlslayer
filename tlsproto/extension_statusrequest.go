// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

const (
	// OCSPStatusRequest constant used for status request oscp
	OCSPStatusRequest uint8 = 1
)

func decodeExtStatusRequest(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	if len(data) > 1 {
		switch data[0] {
		case OCSPStatusRequest:
			info.OSCP = true
		}
	}

	return nil
}
