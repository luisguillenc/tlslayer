// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"

	"github.com/luisguillenc/tlslayer"
)

const (
	serverHelloRandomLen = 32
)

// ServerHelloData stores data from ServerHello messages
type ServerHelloData struct {
	ServerVersion     tlslayer.ProtocolVersion `json:"serverVersion"`
	Random            []byte                   `json:"random,omitempty"`
	SessionID         []byte                   `json:"sessionID,omitempty"`
	CipherSuiteSel    CipherSuite              `json:"cipherSuiteSel"`
	CompressMethodSel CompressionMethod        `json:"compressMethodSel"`

	ExtensionsLen uint16          `json:"extensionsLen"`
	Extensions    []Extension     `json:"extensions,omitempty"`
	ExtInfo       *ExtensionsInfo `json:"extInfo,omitempty"`
}

func (hs *ServerHelloData) String() string {
	str := fmt.Sprintln("Version:", hs.ServerVersion)
	str += fmt.Sprintf("SessionID: %#v\n", hs.SessionID)
	str += fmt.Sprintf("Cipher Suite selected: %v\n", hs.CipherSuiteSel)
	str += fmt.Sprintf("Compression selected: %v\n", hs.CompressMethodSel)
	str += fmt.Sprintln("Extensions:", hs.Extensions)
	str += fmt.Sprintln("Extensions info:", hs.ExtInfo)

	return str
}

//func newServerHelloDataFromBytes(payload []byte) (*ServerHelloData, error) {
func decodeHskServerHello(hsk *Handshake, payload []byte) error {
	if len(payload) < 2 {
		return ErrHandshakeBadLength
	}
	helloData := &ServerHelloData{}
	// Get server version
	helloData.ServerVersion = tlslayer.ProtocolVersion(uint16(payload[0])<<8 | uint16(payload[1]))
	payload = payload[2:]

	// Get random data
	if len(payload) < serverHelloRandomLen {
		return ErrHandshakeBadLength
	}
	helloData.Random = payload[:serverHelloRandomLen]
	payload = payload[serverHelloRandomLen:]

	// Get SessionIDLen
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

	// Get CipherSuite
	if len(payload) < 2 {
		return ErrHandshakeBadLength
	}
	helloData.CipherSuiteSel = CipherSuite(uint16(payload[0])<<8 | uint16(payload[1]))
	payload = payload[2:]

	// Get Compression methods
	if len(payload) < 1 {
		return ErrHandshakeBadLength
	}
	helloData.CompressMethodSel = CompressionMethod(payload[0])
	payload = payload[1:]

	if len(payload) == 0 {
		// no extensions
		hsk.ServerHello = helloData
		return nil
	}

	// Now get extensions
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
		helloData.ExtInfo, err = getExtensionsInfo(HandshakeTypeServerHello, helloData.Extensions)
		if err != nil {
			return err
		}
	}
	hsk.ServerHello = helloData
	return nil
}
