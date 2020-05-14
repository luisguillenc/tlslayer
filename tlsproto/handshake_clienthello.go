// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"

	"github.com/luisguillenc/tlslayer"
)

const (
	clientHelloRandomLen = 32
)

// ClientHelloData stores data from a clienthello handshake
type ClientHelloData struct {
	ClientVersion   tlslayer.ProtocolVersion `json:"clientVersion"`
	Random          []byte                   `json:"random,omitempty"`
	SessionID       []byte                   `json:"sessionID,omitempty"`
	CipherSuites    []CipherSuite            `json:"cipherSuites,omitempty"`
	CompressMethods []CompressionMethod      `json:"compressMethods,omitempty"`

	ExtensionsLen uint16          `json:"extensionsLen"`
	Extensions    []Extension     `json:"extensions,omitempty"`
	ExtInfo       *ExtensionsInfo `json:"extInfo,omitempty"`
}

func (ch *ClientHelloData) String() string {
	str := fmt.Sprintln("Version:", ch.ClientVersion)
	str += fmt.Sprintf("SessionID: %#v\n", ch.SessionID)
	str += fmt.Sprintf("Cipher Suites: %v\n", ch.CipherSuites)
	str += fmt.Sprintf("Compression Methods: %v\n", ch.CompressMethods)
	str += fmt.Sprintf("Extensions: %v\n", ch.Extensions)
	str += fmt.Sprintln("Extensions info:", ch.ExtInfo)

	return str
}

// UseGREASE returns true if clienthello data uses GREASE proposal
func (ch *ClientHelloData) UseGREASE() bool {
	for _, c := range ch.CipherSuites {
		if c.IsGREASE() {
			return true
		}
	}
	for _, e := range ch.Extensions {
		if e.Type.IsGREASE() {
			return true
		}
	}
	if ch.ExtInfo != nil {
		if len(ch.ExtInfo.SignatureSchemes) > 0 {
			for _, sa := range ch.ExtInfo.SignatureSchemes {
				if sa.IsGREASE() {
					return true
				}
			}
		}
		if len(ch.ExtInfo.SupportedGroups) > 0 {
			for _, sg := range ch.ExtInfo.SupportedGroups {
				if sg.IsGREASE() {
					return true
				}
			}
		}
		if len(ch.ExtInfo.SupportedVersions) > 0 {
			for _, sv := range ch.ExtInfo.SupportedVersions {
				if sv.IsGREASE() {
					return true
				}
			}
		}
	}
	return false
}

func decodeHskClientHello(hsk *Handshake, payload []byte) error {
	if len(payload) < 2 {
		return ErrHandshakeBadLength
	}
	helloData := &ClientHelloData{}
	// Get client version
	helloData.ClientVersion = tlslayer.ProtocolVersion(uint16(payload[0])<<8 | uint16(payload[1]))
	payload = payload[2:]

	// Get random data
	if len(payload) < clientHelloRandomLen {
		return ErrHandshakeBadLength
	}
	helloData.Random = payload[:clientHelloRandomLen]
	payload = payload[clientHelloRandomLen:]

	// Get sessionIDLen
	if len(payload) < 1 {
		return ErrHandshakeBadLength
	}
	sessionIDLen := uint32(payload[0])
	payload = payload[1:]

	// Get SessionID
	if len(payload) < int(sessionIDLen) {
		return ErrHandshakeBadLength
	}
	if sessionIDLen != 0 {
		helloData.SessionID = payload[:sessionIDLen]
	}
	payload = payload[sessionIDLen:]

	// Get CipherSuites
	if len(payload) < 2 {
		return ErrHandshakeBadLength
	}
	cipherSuiteLen := uint16(payload[0])<<8 | uint16(payload[1])
	numCiphers := cipherSuiteLen / 2

	if len(payload) < int(cipherSuiteLen) {
		return ErrHandshakeBadLength
	}
	helloData.CipherSuites = make([]CipherSuite, numCiphers)
	for i := 0; i < int(numCiphers); i++ {
		helloData.CipherSuites[i] = CipherSuite(payload[2+2*i])<<8 | CipherSuite(payload[3+2*i])
	}
	payload = payload[2+cipherSuiteLen:]

	// Compression Methods
	if len(payload) < 1 {
		return ErrHandshakeBadLength
	}
	numCompressMethods := int(payload[0])
	if len(payload) < 1+numCompressMethods {
		return ErrHandshakeBadLength
	}
	helloData.CompressMethods = make([]CompressionMethod, numCompressMethods)
	for i := 0; i < int(numCompressMethods); i++ {
		helloData.CompressMethods[i] = CompressionMethod(payload[1+1*i])
	}
	payload = payload[1+numCompressMethods:]

	if len(payload) == 0 {
		// no extensions
		hsk.ClientHello = helloData
		return nil
	}

	// Now get extensions...
	if len(payload) < 2 {
		return ErrHandshakeBadLength
	}
	helloData.ExtensionsLen = uint16(payload[0])<<8 | uint16(payload[1])
	payload = payload[2:]

	if len(payload) != int(helloData.ExtensionsLen) {
		return ErrHandshakeExtBadLength
	}
	var err error
	helloData.Extensions, err = getExtensionsFromBytes(payload)
	if err != nil {
		return err
	}
	if DecodeExtensions {
		helloData.ExtInfo, err = getExtensionsInfo(HandshakeTypeClientHello, helloData.Extensions)
		if err != nil {
			return err
		}
	}
	hsk.ClientHello = helloData
	return nil
}
