// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlslayer

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MaxTLSRecordSize constant with stores the maximum tls record size allowed
const (
	MaxTLSRecordSize uint16 = 16384 + 1024
)

// TLSRecord is the struct for SSL message records
type TLSRecord struct {
	layers.BaseLayer

	Type    ContentType     `json:"type"`
	Version ProtocolVersion `json:"version"`
	Len     uint16          `json:"len"`
}

func (tls *TLSRecord) String() string {
	return fmt.Sprintf("%s %s (len=%d)", tls.Version, tls.Type, tls.Len)
}

// LayerTypeTLSRecord is the registered layer in gopacket
var LayerTypeTLSRecord = gopacket.RegisterLayerType(
	1443,
	gopacket.LayerTypeMetadata{
		Name:    "TLSRecord",
		Decoder: gopacket.DecodeFunc(decodeTLSRecord),
	},
)

// CanDecode satisfaces the interface
func (tls *TLSRecord) CanDecode() gopacket.LayerClass {
	return LayerTypeTLSRecord
}

// LayerType satisfaces the interface
func (tls *TLSRecord) LayerType() gopacket.LayerType {
	return LayerTypeTLSRecord
}

// NextLayerType satisfaces the interface
func (tls *TLSRecord) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload satisfaces the interface and returns the payload of the record
func (tls *TLSRecord) Payload() []byte {
	return tls.BaseLayer.Payload
}

// decodeTLSRecord decodes the byte slice and add tls layer to packet builder
func decodeTLSRecord(data []byte, p gopacket.PacketBuilder) error {
	tls := &TLSRecord{}
	err := tls.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(tls)
	p.SetApplicationLayer(tls)

	return nil
}

// ReadHeader is a helper function that reads a byte slice with the tlsheader
func ReadHeader(data []byte) (ContentType, ProtocolVersion, uint16, error) {
	if len(data) < 5 {
		return 0, 0, 0, ErrTLSWrongSize
	}
	ctype := ContentType(data[0])
	if !ctype.IsValid() {
		return 0, 0, 0, ErrTLSWrongContentType
	}
	pversion := ProtocolVersion(uint16(data[1])<<8 | uint16(data[2]))
	if !pversion.IsValid() {
		return 0, 0, 0, ErrTLSWrongProtocolVersion
	}
	msglen := uint16(data[3])<<8 | uint16(data[4])
	if msglen > MaxTLSRecordSize {
		return 0, 0, 0, ErrTLSWrongSize
	}

	return ctype, pversion, msglen, nil
}

// HasHeader returns true if byte slice has a valid tls record header
func HasHeader(data []byte) bool {
	_, _, _, err := ReadHeader(data)
	return err == nil
}

// DecodeFromBytes load the contents of a tls record from a byte slice
func (tls *TLSRecord) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ctype, pversion, msglen, err := ReadHeader(data)
	if err != nil {
		return err
	}
	tls.Type = ctype
	tls.Version = pversion
	tls.Len = msglen
	tls.BaseLayer.Contents = data[:5]
	//check if data has payload
	if len(data) <= 5 {
		return ErrTLSPayloadEmpty
	}
	tls.BaseLayer.Payload = data[5 : 5+msglen]
	// checks if completed payload
	if len(tls.BaseLayer.Payload) != int(msglen) {
		return ErrTLSWrongPayload
	}
	return nil
}

// IsAlert returns true if record uses Alert protocol
func (tls *TLSRecord) IsAlert() bool {
	return tls.Type == ContentTypeAlert
}

// IsHandshake returns true if record uses Handshake protocol
func (tls *TLSRecord) IsHandshake() bool {
	return tls.Type == ContentTypeHandshake
}

// IsChangeCipherSpec returns true if record uses ChangeCipherSpec protocol
func (tls *TLSRecord) IsChangeCipherSpec() bool {
	return tls.Type == ContentTypeChangeCipherSpec
}

// IsApplicationData returns true if record uses ApplicationData protocol
func (tls *TLSRecord) IsApplicationData() bool {
	return tls.Type == ContentTypeApplicationData
}

// IsClear returns true if payload of the record was cleared
func (tls *TLSRecord) IsClear() bool {
	return tls.Len > 0 && (len(tls.BaseLayer.Payload) == 0)
}

// ClearPayload sets payload empty
func (tls *TLSRecord) ClearPayload() {
	tls.BaseLayer.Payload = nil
}

// Copy makes a full copy of a TLSRecord
func Copy(dst, src *TLSRecord) {
	dst.Type = src.Type
	dst.Version = src.Version
	dst.Len = src.Len
	dst.BaseLayer.Contents = make([]byte, len(src.BaseLayer.Contents), len(src.BaseLayer.Contents))
	copy(dst.BaseLayer.Contents, src.BaseLayer.Contents)
	dst.BaseLayer.Payload = make([]byte, len(src.BaseLayer.Payload), len(src.BaseLayer.Payload))
	copy(dst.BaseLayer.Payload, src.BaseLayer.Payload)
}

// CopyHeader makes a copy of the header of a TLSRecord and sets payload empty
func CopyHeader(dst, src *TLSRecord) {
	dst.Type = src.Type
	dst.Version = src.Version
	dst.Len = src.Len
	dst.BaseLayer.Contents = make([]byte, len(src.BaseLayer.Contents), len(src.BaseLayer.Contents))
	copy(dst.BaseLayer.Contents, src.BaseLayer.Contents)
	dst.BaseLayer.Payload = nil
}

func init() {
	layers.RegisterTCPPortLayerType(443, LayerTypeTLSRecord)
}
