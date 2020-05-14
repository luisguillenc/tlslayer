// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import "fmt"

// SupportedGroup is a supported group in format defined by rfc
type SupportedGroup uint16

var supportedGroupReg = map[SupportedGroup]string{
	0:     "reserved",
	1:     "sect163k1",
	2:     "sect163r1",
	3:     "sect163r2",
	4:     "sect193r1",
	5:     "sect193r2",
	6:     "sect233k1",
	7:     "sect233r1",
	8:     "sect239k1",
	9:     "sect283k1",
	10:    "sect283r1",
	11:    "sect409k1",
	12:    "sect409r1",
	13:    "sect571k1",
	14:    "sect571r1",
	15:    "secp160k1",
	16:    "secp160r1",
	17:    "secp160r2",
	18:    "secp192k1",
	19:    "secp192r1",
	20:    "secp224k1",
	21:    "secp224r1",
	22:    "secp256k1",
	23:    "secp256r1",
	24:    "secp384r1",
	25:    "secp521r1",
	26:    "brainpoolP256r1",
	27:    "brainpoolP384r1",
	28:    "brainpoolP512r1",
	29:    "x25519",
	30:    "x448",
	256:   "ffdhe2048",
	257:   "ffdhe3072",
	258:   "ffdhe4096",
	259:   "ffdhe6144",
	260:   "ffdhe8192",
	65280: "unassigned",
	65281: "arbitrary_explicit_prime_curves",
	65282: "arbitrary_explicit_char2_curves",
}

func (sg SupportedGroup) getDesc() string {
	if name, ok := supportedGroupReg[sg]; ok {
		return name
	}
	n := uint16(sg)
	if n >= 31 && n <= 255 {
		return "unassigned"
	} else if n >= 261 && n <= 507 {
		return "unassigned"
	} else if n >= 508 && n <= 511 {
		return "reserved"
	} else if n >= 512 && n <= 65023 {
		return "unassigned"
	} else if n >= 65024 && n <= 65279 {
		return "reserved"
	} else if n >= 65283 && n <= 65535 {
		return "unassigned"
	}

	return "unknown"
}
func (sg SupportedGroup) String() string {
	return fmt.Sprintf("%s(%d)", sg.getDesc(), sg)
}

// IsGREASE returns true if passed signature and hash is in GREASE spec
func (sg SupportedGroup) IsGREASE() bool {
	return isGREASE16(uint16(sg))
}

// ECPointFormat is an eliptic curve format defined by rfc
type ECPointFormat int //nota: lo hago de tipo int porque sino mongo lo almacena como si fuese un bytearray

func (e ECPointFormat) getDesc() string {
	n := uint8(e)
	if n == 0 {
		return "uncompressed"
	} else if n == 1 {
		return "ansiX962_compressed_prime"
	} else if n == 2 {
		return "ansiX962_compressed_char2"
	} else if n >= 3 && n <= 247 {
		return "unassigned"
	} else if n > 248 {
		return "reserved_private"
	}

	return "unknown"
}

func (e ECPointFormat) String() string {
	return fmt.Sprintf("%s(%d)", e.getDesc(), e)
}

func decodeExtSupportedGroups(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	if len(data) < 2 {
		return ErrHandshakeExtBadLength
	}
	groupLen := int(data[0])<<8 | int(data[1])

	data = data[2:]

	if len(data) < groupLen {
		// Malformed length
		return ErrHandshakeExtBadLength
	}

	info.SupportedGroups = make([]SupportedGroup, groupLen/2)
	for i := 0; i < groupLen/2; i++ {
		info.SupportedGroups[i] = SupportedGroup(uint16(data[i*2])<<8 | uint16(data[i*2+1]))
	}

	return nil
}

func decodeExtECPointFormats(info *ExtensionsInfo, ht HandshakeType, data []byte) error {
	if len(data) < 1 {
		return ErrHandshakeExtBadLength
	}
	pointLen := int(data[0])

	data = data[1:]

	if len(data) < pointLen {
		return ErrHandshakeExtBadLength
	}

	info.ECPointFormats = make([]ECPointFormat, pointLen)
	for i := 0; i < pointLen; i++ {
		info.ECPointFormats[i] = ECPointFormat(data[i])
	}

	return nil
}
