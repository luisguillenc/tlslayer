// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

var grease16 = []uint16{
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
	0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
	0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
	0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

var grease8 = []uint8{
	0x0B, 0x2A, 0x49, 0x68,
	0x87, 0xA6, 0xC5, 0xE4,
}

func isGREASE16(code uint16) bool {
	for _, gr := range grease16 {
		if code == gr {
			return true
		}
	}
	return false
}

func isGREASE8(code uint8) bool {
	for _, gr := range grease8 {
		if code == gr {
			return true
		}
	}
	return false
}
