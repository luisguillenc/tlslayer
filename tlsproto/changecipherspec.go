// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"

	"github.com/luisguillenc/tlslayer"
)

// CipherSpecType is the value for cipherspec protocol
type CipherSpecType int8

// Valid values
const (
	CCSChange CipherSpecType = 1
)

func (c CipherSpecType) getDesc() string {
	if c == CCSChange {
		return "change_cipher_spec"
	}
	return "unknown"
}

func (c CipherSpecType) String() string {
	return fmt.Sprintf("%s(%d)", c.getDesc(), c)
}

// IsValid returns true
func (c CipherSpecType) IsValid() bool {
	return c == CCSChange
}

// ChangeCipherSpec is the struct for tls messages of changecipherspec protocol
type ChangeCipherSpec struct {
	TLSMessage

	Type CipherSpecType `json:"type"`
}

func (ccs *ChangeCipherSpec) String() string {
	return fmt.Sprint(ccs.Type)
}

// GetType returns the content type
func (ccs *ChangeCipherSpec) GetType() tlslayer.ContentType {
	return tlslayer.ContentTypeChangeCipherSpec
}

// NewChangeCipherSpecFromBytes creates a changecipherspec from a byte slice with the payload
func NewChangeCipherSpecFromBytes(payload []byte) (*ChangeCipherSpec, error) {
	if len(payload) < 1 {
		return nil, ErrWrowngLenPayload
	}

	ctype := CipherSpecType(payload[0])
	if !ctype.IsValid() {
		return nil, ErrCCSInvalidValue
	}

	ccs := &ChangeCipherSpec{Type: ctype}

	return ccs, nil
}

// NewChangeCipherSpecFromRecord creates an changecipherspec from a TLS Record
func NewChangeCipherSpecFromRecord(tlsr *tlslayer.TLSRecord) (*ChangeCipherSpec, error) {
	if tlsr.Type != tlslayer.ContentTypeChangeCipherSpec {
		return nil, ErrUnexpectedRecordType
	}
	if len(tlsr.Payload()) != 1 {
		return nil, ErrWrowngLenPayload
	}
	return NewChangeCipherSpecFromBytes(tlsr.Payload())
}
