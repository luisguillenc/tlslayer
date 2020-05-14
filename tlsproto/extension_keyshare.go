// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import "fmt"

// KeyShareEntry is a struct that stores a key
type KeyShareEntry struct {
	Group SupportedGroup `json:"group"`
	Key   []byte         `json:"key,omitempty"`
}

// PSKKeyExchangeMode represents..
type PSKKeyExchangeMode uint8

func (e PSKKeyExchangeMode) getDesc() string {
	if e.IsGREASE() {
		return "GREASE"
	}
	n := uint8(e)
	if n == 0 {
		return "psk_ke"
	} else if n == 1 {
		return "psk_dhe_ke"
	} else if n >= 2 && n <= 253 {
		return "unassigned"
	} else if n > 254 {
		return "reserved_private"
	}

	return "unknown"
}

func (e PSKKeyExchangeMode) String() string {
	return fmt.Sprintf("%s(%d)", e.getDesc(), e)
}

// IsGREASE returns true if is a grease value
func (e PSKKeyExchangeMode) IsGREASE() bool {
	return isGREASE8(uint8(e))
}

func decodeExtKeyShare(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	switch ht {
	case HandshakeTypeClientHello:
		if len(data) < 2 {
			return ErrHandshakeExtBadLength
		}
		keysLen := uint16(data[0])<<8 | uint16(data[1])
		data = data[2:]

		if len(data) != int(keysLen) {
			return ErrHandshakeExtBadLength
		}
		info.KeyShareEntries = make([]KeyShareEntry, 0)
		for len(data) > 0 {
			if len(data) < 4 {
				return ErrHandshakeExtBadLength
			}
			group := uint16(data[0])<<8 | uint16(data[1])
			keylen := uint16(data[2])<<8 | uint16(data[3])

			entry := KeyShareEntry{}
			entry.Group = SupportedGroup(group)
			entry.Key = data[4 : 4+keylen]

			info.KeyShareEntries = append(info.KeyShareEntries, entry)
			data = data[4+keylen:]
		}
	case HandshakeTypeServerHello:
		info.KeyShareEntries = make([]KeyShareEntry, 0, 1)
		if len(data) < 4 {
			return ErrHandshakeExtBadLength
		}
		group := uint16(data[0])<<8 | uint16(data[1])
		keylen := uint16(data[2])<<8 | uint16(data[3])

		entry := KeyShareEntry{}
		entry.Group = SupportedGroup(group)
		entry.Key = data[4 : 4+keylen]

		info.KeyShareEntries = append(info.KeyShareEntries, entry)
	}
	return nil
}

func decodeExtPSKKeyExchangeModes(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	if len(data) < 1 {
		return ErrHandshakeExtBadLength
	}
	modesLen := uint8(data[0])
	data = data[1:]

	if len(data) != int(modesLen) {
		return ErrHandshakeExtBadLength
	}

	info.PSKKeyExchangeModes = make([]PSKKeyExchangeMode, int(modesLen), int(modesLen))
	for i := 0; i < int(modesLen); i++ {
		info.PSKKeyExchangeModes[i] = PSKKeyExchangeMode(data[i])
	}

	return nil
}
