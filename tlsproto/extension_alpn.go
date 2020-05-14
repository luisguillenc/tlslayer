// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

func decodeExtALPN(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	if len(data) < 2 {
		return ErrHandshakeExtBadLength
	}

	alpnLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	if len(data) != alpnLen {
		return ErrHandshakeExtBadLength
	}

	for len(data) > 0 {
		stringLen := int(data[0])
		data = data[1:]
		info.ALPNs = append(info.ALPNs, string(data[:stringLen]))
		data = data[stringLen:]
	}

	return nil
}
