// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"

	"github.com/luisguillenc/tlslayer"
)

var DecodeExtensions bool = true

// HandshakeType defines the type of handshake
type HandshakeType uint8

// Constants of HandshakeType
const (
	HandshakeTypeHelloRequest       HandshakeType = 0
	HandshakeTypeClientHello        HandshakeType = 1
	HandshakeTypeServerHello        HandshakeType = 2
	HandshakeTypeNewSessionTicket   HandshakeType = 4
	HandshakeTypeEndOfEarlyData     HandshakeType = 5
	HandshakeTypeCertificate        HandshakeType = 11
	HandshakeTypeServerKeyExchange  HandshakeType = 12
	HandshakeTypeCertificateRequest HandshakeType = 13
	HandshakeTypeServerHelloDone    HandshakeType = 14
	HandshakeTypeCertificateVerify  HandshakeType = 15
	HandshakeTypeClientKeyExchange  HandshakeType = 16
	HandshakeTypeFinished           HandshakeType = 20
	HandshakeTypeCertificateURL     HandshakeType = 21
	HandshakeTypeCertificateStatus  HandshakeType = 22
	HandshakeTypeKeyUpdate          HandshakeType = 24
)

// decodeHskMsg is a function prototype that decodes handshake messages
type decodeHskMsg func(hsk *Handshake, data []byte) error

// HandShakeTypeReg is a map with strings of alert description
var handShakeTypeReg = map[HandshakeType]struct {
	desc    string
	decoder decodeHskMsg
}{
	HandshakeTypeHelloRequest:       {"hello_request", nil},
	HandshakeTypeClientHello:        {"client_hello", decodeHskClientHello},
	HandshakeTypeServerHello:        {"server_hello", decodeHskServerHello},
	HandshakeTypeNewSessionTicket:   {"new_session_ticket", nil},
	HandshakeTypeEndOfEarlyData:     {"end_of_early_data", nil},
	HandshakeTypeCertificate:        {"certificate", decodeHskCertificate},
	HandshakeTypeServerKeyExchange:  {"server_key_exchange", nil},
	HandshakeTypeCertificateRequest: {"certificate_request", nil},
	HandshakeTypeServerHelloDone:    {"server_hello_done", nil},
	HandshakeTypeCertificateVerify:  {"certificate_verify", nil},
	HandshakeTypeClientKeyExchange:  {"client_key_exchange", nil},
	HandshakeTypeFinished:           {"finished", nil},
	HandshakeTypeCertificateURL:     {"certificate_url", nil},
	HandshakeTypeCertificateStatus:  {"certificate_status", nil},
	HandshakeTypeKeyUpdate:          {"key_update", nil},
}

func (hst HandshakeType) getDesc() string {
	if h, ok := handShakeTypeReg[hst]; ok {
		return h.desc
	}
	return "unknown"
}

func (hst HandshakeType) String() string {
	return fmt.Sprintf("%s(%d)", hst.getDesc(), hst)
}

// IsValid method checks if it's a valid value
func (hst HandshakeType) IsValid() bool {
	_, ok := handShakeTypeReg[hst]
	return ok
}

// Handshake is the structure for handshake
type Handshake struct {
	TLSMessage

	Type HandshakeType `json:"type"`
	Len  uint32        `json:"len"`

	ClientHello *ClientHelloData `json:"clientHello,omitempty"`
	ServerHello *ServerHelloData `json:"serverHello,omitempty"`
	Certificate *CertificateData `json:"certificate,omitempty"`
}

func (hs *Handshake) String() string {
	return fmt.Sprintf("%s (len=%d)", hs.Type, hs.Len)
}

// GetType returns the content type
func (hs *Handshake) GetType() tlslayer.ContentType {
	return tlslayer.ContentTypeHandshake
}

// GetHandshakeType returns the handshake message type
func (hs *Handshake) GetHandshakeType() HandshakeType {
	return hs.Type
}

// IsClientHello returns true if handshake is client hello
func (hs *Handshake) IsClientHello() bool {
	return hs.Type == HandshakeTypeClientHello
}

// IsServerHello returns true if handshake is server hello
func (hs *Handshake) IsServerHello() bool {
	return hs.Type == HandshakeTypeServerHello
}

// ReadHandshakeHeader reads header of a handshake message and return values
func ReadHandshakeHeader(bytes []byte) (HandshakeType, uint32, error) {
	if len(bytes) < 4 {
		return 0, 0, ErrHandshakeWrongSize
	}
	htype := HandshakeType(bytes[0])
	if !htype.IsValid() {
		return 0, 0, ErrHandshakeWrongType
	}
	hlen := uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	// TODO: comprobar longitud máxima de handshake

	return htype, hlen, nil
}

// NewHandshakeFromBytes creates a handshake from a byte slice with the payload
func NewHandshakeFromBytes(payload []byte) (*Handshake, error) {
	htype, hlen, err := ReadHandshakeHeader(payload)
	if err != nil {
		return nil, err
	}
	// check if payload is completed
	if int(hlen) != len(payload)-4 {
		return nil, ErrHandshakePayloadMissmatch
	}
	// creates handshake
	handshake := &Handshake{}
	handshake.Type = htype
	handshake.Len = hlen
	// decode payload
	hskpayload := payload[4:]
	h, _ := handShakeTypeReg[htype]
	if h.decoder != nil {
		err = h.decoder(handshake, hskpayload)
	}
	return handshake, err
}

// NewHandshakesFromRecord creates a slice with handshakes from a byte slice with the payload
func NewHandshakesFromRecord(tlsr *tlslayer.TLSRecord) ([]*Handshake, error) {
	if tlsr.Type != tlslayer.ContentTypeHandshake {
		return nil, ErrUnexpectedRecordType
	}
	// manages multiple handshakes messages in a tls record
	payload := tlsr.Payload()
	handshakes := make([]*Handshake, 0)
	for len(payload) > 0 {
		_, hlen, err := ReadHandshakeHeader(payload)
		if err != nil {
			return nil, err
		}
		if int(hlen) > len(payload)-4 {
			// handshake is fragmented
			return nil, ErrHandshakeFragmented
		}
		bytes := payload[:hlen+4]
		handshake, err := NewHandshakeFromBytes(bytes)
		if err != nil {
			return nil, err
		}
		handshakes = append(handshakes, handshake)

		// next handshake
		payload = payload[hlen+4:]
	}
	return handshakes, nil
}
