// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.
package tlsproto

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/luisguillenc/tlslayer"
)

var testRecordAlert1 = []byte{
	0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00,
}

var testRecordAlert2 = []byte{
	0x15, 0x03, 0x03, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xeb, 0xd0, 0x7f,
	0xd9, 0xfb, 0x3e, 0x85, 0x3a, 0xe1, 0x8b, 0x6d, 0xe1, 0xc8, 0x29, 0x96, 0x82, 0x8f, 0x96,
}

func TestDecodeAlertTLSRecord(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordAlert1, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	alert, err := NewAlertFromRecord(tlsrecord)
	if err != nil {
		t.Error("Error getting alert from TLSRecord")
		return
	}

	if alert.Level != AlertLevelWarning {
		t.Error("Error getting alert level")
	}

	if alert.Description != AlertCloseNotify {
		t.Error("Error getting alert description")
	}
}

func TestDecodeAlertCrypted(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordAlert2, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	_, err := NewAlertFromRecord(tlsrecord)
	if err != ErrWrowngLenPayload {
		t.Errorf("Expected error: %v, but got: %v", ErrWrowngLenPayload, err)
		return
	}
}
