// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.
package tlsproto

import (
	"bufio"
	"bytes"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/luisguillenc/tlslayer"
)

const (
	pathBinFiles = "../test/data"
)

func loadBinFile(bindata *[]byte, binfile string) error {
	file, err := os.Open(pathBinFiles + "/" + binfile)

	if err != nil {
		return err
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return statsErr
	}

	size := stats.Size()
	*bindata = make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(*bindata)

	return err
}

var testDecodeOptions = gopacket.DecodeOptions{
	DecodeStreamsAsDatagrams: true,
}

// this file tests
var testRecordClientHello1 []byte
var testRecordServerHello1 []byte
var testRecordCertificate1 []byte
var testRecordMultipleHsk1 []byte
var testRecordGREASE1 []byte

func init() {
	var loadFiles = []struct {
		vardata *[]byte
		binfile string
	}{
		{&testRecordClientHello1, "tlsr-hsk-clienthello1.bin"},
		{&testRecordServerHello1, "tlsr-hsk-serverhello1.bin"},
		{&testRecordCertificate1, "tlsr-hsk-certificate1.bin"},
		{&testRecordMultipleHsk1, "tlsr-hsk-multiple1.bin"},
		{&testRecordGREASE1, "tlsr-hsk-clienthello-grease1.bin"},
	}
	for _, f := range loadFiles {
		err := loadBinFile(f.vardata, f.binfile)
		if err != nil {
			panic("unable to load " + f.binfile)
		}
	}
}

func checkLayers(p gopacket.Packet, want []gopacket.LayerType, t *testing.T) {
	layers := p.Layers()
	t.Log("Checking packet layers, want", want)
	for _, l := range layers {
		t.Logf("  Got layer %v, %d bytes, payload of %d bytes", l.LayerType(),
			len(l.LayerContents()), len(l.LayerPayload()))
	}
	t.Log(p)
	if len(layers) != len(want) {
		t.Errorf("  Number of layers mismatch: got %d want %d", len(layers),
			len(want))
		return
	}
	for i, l := range layers {
		if l.LayerType() != want[i] {
			t.Errorf("  Layer %d mismatch: got %v want %v", i, l.LayerType(),
				want[i])
		}
	}
}

func TestDecodeClientHello1(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordClientHello1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshakes, err := NewHandshakesFromRecord(tlsrecord)
	if err != nil {
		t.Fatal("getting handshakes from record:", err)
	}
	if len(handshakes) != 1 {
		t.Fatal("incorrect number of handshakes in record: ", len(handshakes))
	}
	handshake := handshakes[0]
	if handshake.GetType() != tlslayer.ContentTypeHandshake {
		t.Errorf("expected type: %v, got: %v", tlslayer.ContentTypeHandshake, handshake.GetType())
	}
	if handshake.Type != HandshakeTypeClientHello {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeClientHello, handshake.Type)
	}
	if handshake.GetHandshakeType() != HandshakeTypeClientHello {
		t.Error("getting handhake type")
	}
	if handshake.Len != 508 {
		t.Errorf("expected len: 508, got: %v", handshake.Len)
	}
	ch := handshake.ClientHello
	if ch == nil {
		t.Fatal("ClientHello doesn't decoded")
	}
	if ch.ClientVersion != tlslayer.VersionTLS12 {
		t.Errorf("expected version: %v, got: %v", tlslayer.VersionTLS12, ch.ClientVersion)
	}
	var random = []byte{
		0x8a, 0x5f, 0x29, 0xe8, 0xc1, 0xa3, 0xdd, 0xad, 0xec, 0x09, 0x8a, 0x6e, 0xc8, 0x68, 0x2f, 0x67,
		0x70, 0x12, 0x73, 0xfb, 0x91, 0x26, 0xab, 0x36, 0x74, 0x5b, 0x84, 0x40, 0x5e, 0xe1, 0xe6, 0x00,
	}
	if bytes.Compare(ch.Random, random) != 0 {
		t.Error("random value mismatch")
	}
	if len(ch.CompressMethods) != 1 {
		t.Errorf("expected compressmethods: 1, got: %v", len(ch.CompressMethods))
	} else {
		if ch.CompressMethods[0] != CompressionMethodNull {
			t.Errorf("expected compress: %v, got: %v", CompressionMethodNull, ch.CompressMethods[0])
		}
	}
	if len(ch.CipherSuites) != 14 {
		t.Errorf("expected ciphersuites: 14, got: %v", len(ch.CipherSuites))
	} else {
		if ch.CipherSuites[12] != CipherSuite(0x0035) {
			t.Errorf("expected ciphersuite: %v, got: %v", CipherSuite(0x0035), ch.CipherSuites[12])
		}
	}
	if ch.ExtensionsLen != 407 {
		t.Errorf("expected extensions len: 407, got: %v", ch.ExtensionsLen)
	}
	if len(ch.Extensions) != 13 {
		t.Errorf("expected extensions: 13, got: %v", len(ch.Extensions))
	}
}

func TestDecodeClientHello1Ext(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordClientHello1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshakes, err := NewHandshakesFromRecord(tlsrecord)
	if err != nil {
		t.Fatal("getting handshakes from record:", err)
	}
	if len(handshakes) != 1 {
		t.Fatal("incorrect number of handshakes in record: ", len(handshakes))
	}
	handshake := handshakes[0]
	if handshake.GetType() != tlslayer.ContentTypeHandshake {
		t.Errorf("expected type: %v, got: %v", tlslayer.ContentTypeHandshake, handshake.GetType())
	}
	if handshake.Type != HandshakeTypeClientHello {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeClientHello, handshake.Type)
	}
	ch := handshake.ClientHello
	if ch == nil {
		t.Fatal("ClientHello doesn't decoded")
	}
	if ch.ExtInfo == nil {
		t.Fatalf("extinfo doesn't decoded")
	}
	if ch.ExtInfo.SNI != "tiles.services.mozilla.com" {
		t.Errorf("expected SNI: tiles.services.mozilla.com, got: %v", ch.ExtInfo.SNI)
	}
	if len(ch.ExtInfo.SignatureSchemes) != 11 {
		t.Errorf("expected signature_algorithms: (len=11), got: (len=%v)", len(ch.ExtInfo.SignatureSchemes))
	} else {
		if ch.ExtInfo.SignatureSchemes[6] != SignatureScheme(0x0401) {
			t.Errorf("expected signature_algorithms[6]: %v, got: %v", SignatureScheme(0x0401), ch.ExtInfo.SignatureSchemes[6])
		}
	}
	if len(ch.ExtInfo.SupportedVersions) != 4 {
		t.Errorf("expected supported_versions len: 4, got: %v", len(ch.ExtInfo.SupportedVersions))
	} else {
		if ch.ExtInfo.SupportedVersions[0] != SupportedVersion(0x7f1c) {
			t.Errorf("expected supported_version[0]: %v, got: %v", SupportedVersion(0x7f1c), ch.ExtInfo.SupportedVersions[0])
		}
		if ch.ExtInfo.SupportedVersions[3] != SupportedVersion(0x0301) {
			t.Errorf("expected supported_version[3]: %v, got: %v", SupportedVersion(0x0301), ch.ExtInfo.SupportedVersions[3])
		}
	}
	if len(ch.ExtInfo.SupportedGroups) != 6 {
		t.Errorf("expected supportedgroups: 6, got: %v", len(ch.ExtInfo.SupportedGroups))
	} else {
		if ch.ExtInfo.SupportedGroups[4] != SupportedGroup(0x0100) {
			t.Errorf("expected supportedgroup: %v, got: %v", SupportedGroup(0x0100), ch.ExtInfo.SupportedGroups[4])
		}
	}
	if len(ch.ExtInfo.ECPointFormats) != 1 {
		t.Errorf("expected ecpointformats: 1, got: %v", len(ch.ExtInfo.ECPointFormats))
	} else {
		if ch.ExtInfo.ECPointFormats[0] != ECPointFormat(0) {
			t.Errorf("expected ecpointformat: %v, got: %v", ECPointFormat(0), ch.ExtInfo.ECPointFormats[0])
		}
	}
	if len(ch.ExtInfo.ALPNs) != 2 {
		t.Errorf("expected ALPNs: 2, got: %v", len(ch.ExtInfo.ALPNs))
	} else {
		if ch.ExtInfo.ALPNs[1] != "http/1.1" {
			t.Errorf("expected ALPN: http/1.1, got: %v", ch.ExtInfo.ALPNs[1])
		}
	}
	if !ch.ExtInfo.OSCP {
		t.Errorf("expected OSCP")
	}
}

func TestDecodeServerHello(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordServerHello1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshake, err := NewHandshakeFromBytes(tlsrecord.Payload())
	if err != nil {
		t.Fatal("getting handshake from record:", err)
	}
	if handshake.Type != HandshakeTypeServerHello {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeServerHello, handshake.Type)
	}
	if handshake.Len != 85 {
		t.Errorf("expected len: 85, got: %v", handshake.Len)
	}
	sh := handshake.ServerHello
	if sh == nil {
		t.Fatal("ServerHello doesn't decoded")
	}
	if sh.ServerVersion != tlslayer.VersionTLS12 {
		t.Errorf("expected version: %v, got: %v", tlslayer.VersionTLS12, sh.ServerVersion)
	}
	var random = []byte{
		0xc6, 0x0b, 0xc8, 0xee, 0xce, 0x14, 0x6e, 0x0d, 0x3b, 0x60, 0xc5, 0x94, 0xb0, 0xb3, 0xa8, 0x8e,
		0x0a, 0x77, 0xa6, 0x9e, 0xc1, 0xdd, 0x68, 0x14, 0x88, 0x02, 0x29, 0x74, 0x18, 0x4e, 0xc8, 0xe4,
	}
	if bytes.Compare(sh.Random, random) != 0 {
		t.Error("random value mismatch")
	}
	if sh.CompressMethodSel != CompressionMethodNull {
		t.Errorf("expected compress: %v, got: %v", CompressionMethodNull, sh.CompressMethodSel)
	}
	if sh.CipherSuiteSel != CipherSuite(0xc02f) {
		t.Errorf("expected ciphersuite: %v, got: %v", CipherSuite(0xc02f), sh.CipherSuiteSel)
	}
	if sh.ExtensionsLen != 13 {
		t.Errorf("expected extensions len: 13, got: %v", sh.ExtensionsLen)
	}
	if len(sh.Extensions) != 2 {
		t.Errorf("expected extensions: 2, got: %v", len(sh.Extensions))
	}
	if len(sh.ExtInfo.ECPointFormats) != 3 {
		t.Errorf("expected ecpointformats: 3, got: %v", len(sh.ExtInfo.ECPointFormats))
	} else {
		if sh.ExtInfo.ECPointFormats[1] != ECPointFormat(1) {
			t.Errorf("expected ecpointformat: %v, got: %v", ECPointFormat(1), sh.ExtInfo.ECPointFormats[1])
		}
	}
}

func TestDecodeCertificate(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordCertificate1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshake, err := NewHandshakeFromBytes(tlsrecord.Payload())
	if err != nil {
		t.Fatal("getting handshake from record:", err)
	}
	if handshake.Type != HandshakeTypeCertificate {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeCertificate, handshake.Type)
	}
	if handshake.Len != 2564 {
		t.Errorf("expected len: 2564, got: %v", handshake.Len)
	}
	certh := handshake.Certificate
	if certh == nil {
		t.Fatal("CertificateData doesn't loaded")
	}
	if certh.CertificatesLen != 2561 {
		t.Errorf("expected certificateslen: 2561, got: %v", certh.CertificatesLen)
	}
	if len(certh.Certificates) != 2 {
		t.Errorf("expected certificates: 2, got: %v", len(certh.Certificates))
	} else {
		if certh.Certificates[0].Subject.CommonName != "*.services.mozilla.com" {
			t.Errorf("expected commonname: *.services.mozilla.com, got: %v", certh.Certificates[0].Subject.CommonName)
		}
	}
}

func TestMultipleHandshake(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordMultipleHsk1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshakes, err := NewHandshakesFromRecord(tlsrecord)
	if err != nil {
		t.Fatal("getting handshakes from record:", err)
	}
	if len(handshakes) != 3 {
		t.Fatal("incorrect number of handshakes in record: ", len(handshakes))
	}
	hsk1 := handshakes[0]
	if hsk1.Type != HandshakeTypeServerHello {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeServerHello, hsk1.Type)
	}
	if hsk1.Len != 70 {
		t.Errorf("expected len: 70, got: %v", hsk1.Len)
	}
	hsk2 := handshakes[1]
	if hsk2.Type != HandshakeTypeCertificate {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeCertificate, hsk2.Type)
	}
	if hsk2.Len != 2628 {
		t.Errorf("expected len: 2628, got: %v", hsk2.Len)
	}
	hsk3 := handshakes[2]
	if hsk3.Type != HandshakeTypeServerHelloDone {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeServerHelloDone, hsk3.Type)
	}
	if hsk3.Len != 0 {
		t.Errorf("expected len: 0, got: %v", hsk3.Len)
	}
}

func TestGREASE(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordGREASE1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshake, err := NewHandshakeFromBytes(tlsrecord.Payload())
	if err != nil {
		t.Fatal("getting handshake from bytes:", err)
	}
	if handshake.Type != HandshakeTypeClientHello {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeClientHello, handshake.Type)
	}
	if handshake.Len != 508 {
		t.Errorf("expected len: 508, got: %v", handshake.Len)
	}
	ch := handshake.ClientHello
	if ch == nil {
		t.Fatal("ClientHello doesn't decoded")
	}
	if len(ch.CipherSuites) != 14 {
		t.Fatalf("expected ciphersuites: 14, got: %v", len(ch.CipherSuites))
	}
	if !ch.CipherSuites[0].IsGREASE() {
		t.Errorf("expected ciphersuite grease: %v, got: %v", CipherSuite(0x3a3a), ch.CipherSuites[0])
	}
	if ch.CipherSuites[1].IsGREASE() {
		t.Errorf("expected ciphersuite not grease: %v, got: %v", CipherSuite(0xcca9), ch.CipherSuites[1])
	}
	if len(ch.Extensions) != 14 {
		t.Fatalf("expected extensions: 14, got: %v", len(ch.Extensions))
	}
	if !ch.Extensions[12].Type.IsGREASE() {
		t.Errorf("expected extension grease: %v, got: %v", ExtensionType(0x9a9a), ch.Extensions[12].Type)
	}
	if ch.Extensions[13].Type.IsGREASE() {
		t.Errorf("expected extension grease: %v, got: %v", ExtPadding, ch.Extensions[13].Type)
	}
}

func TestExtKeyShare1(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordClientHello1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshake, err := NewHandshakeFromBytes(tlsrecord.Payload())
	if err != nil {
		t.Fatal("getting handshake from bytes:", err)
	}
	if handshake.Type != HandshakeTypeClientHello {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeClientHello, handshake.Type)
	}
	ch := handshake.ClientHello
	if ch == nil {
		t.Fatal("ClientHello doesn't decoded")
	}
	if len(ch.ExtInfo.KeyShareEntries) != 2 {
		t.Errorf("expected key_share: (len=2), got: %v", len(ch.ExtInfo.KeyShareEntries))
	} else {
		if ch.ExtInfo.KeyShareEntries[0].Group != SupportedGroup(29) {
			t.Errorf("expected key_share[0].Group: %v, got: %v", SupportedGroup(29), ch.ExtInfo.KeyShareEntries[0].Group)
		}
		if len(ch.ExtInfo.KeyShareEntries[0].Key) != 32 {
			t.Errorf("expected key_share[0].Key: (len=32), got: (len=%v)", len(ch.ExtInfo.KeyShareEntries[0].Key))
		}
		if ch.ExtInfo.KeyShareEntries[1].Group != SupportedGroup(23) {
			t.Errorf("expected key_share[0].Group: %v, got: %v", SupportedGroup(23), ch.ExtInfo.KeyShareEntries[1].Group)
		}
		if len(ch.ExtInfo.KeyShareEntries[1].Key) != 65 {
			t.Errorf("expected key_share[0].Key: (len=65), got: (len=%v)", len(ch.ExtInfo.KeyShareEntries[1].Key))
		}
	}
}

func TestExtPSKKeyExchangeModes(t *testing.T) {
	tlsrecord := &tlslayer.TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordClientHello1, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("bad tlsrecord")
	}
	handshake, err := NewHandshakeFromBytes(tlsrecord.Payload())
	if err != nil {
		t.Fatal("getting handshake from bytes:", err)
	}
	if handshake.Type != HandshakeTypeClientHello {
		t.Errorf("expected handshake type: %v, got: %v", HandshakeTypeClientHello, handshake.Type)
	}
	ch := handshake.ClientHello
	if ch == nil {
		t.Fatal("ClientHello doesn't decoded")
	}
	if len(ch.ExtInfo.PSKKeyExchangeModes) != 1 {
		t.Errorf("expected psk_key_exchange_modes: (len=1), got: %v", len(ch.ExtInfo.PSKKeyExchangeModes))
	} else {
		if ch.ExtInfo.PSKKeyExchangeModes[0] != PSKKeyExchangeMode(1) {
			t.Errorf("expected psk_key_exchange_modes[0]: %v, got: %v", PSKKeyExchangeMode(1), ch.ExtInfo.PSKKeyExchangeModes[0])
		}
	}
}
