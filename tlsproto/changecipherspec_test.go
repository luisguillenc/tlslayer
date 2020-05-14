// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.
package tlsproto

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/luisguillenc/tlslayer"
)

var testRecordCCS1 = []byte{
	0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
}

var testBadRecordCCS1 = []byte{
	0x14, 0x03, 0x03, 0x00, 0x01, 0x03, 0x04,
}

func TestDecodeCCS(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordCCS1, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	ccs, err := NewChangeCipherSpecFromRecord(tlsrecord)
	if err != nil {
		t.Error("Error getting ccs")
		return
	}

	if ccs.Type != CCSChange {
		t.Error("Error getting ccs type")
	}
}

func TestDecodeBadCCS(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testBadRecordCCS1, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	_, err := NewChangeCipherSpecFromRecord(tlsrecord)
	if err != ErrCCSInvalidValue {
		t.Errorf("Expected error: %v, but got: %v", ErrCCSInvalidValue, err)
		return
	}
}
