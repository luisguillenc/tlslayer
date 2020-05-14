// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.
package tlslayer

import (
	"bufio"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	pathBinFiles = "test/data"
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

var testPacketClient []byte
var testPacketServer1 []byte
var testPacketServer2 []byte
var testRecordServerHello []byte
var testRecordCCS []byte
var testRecordEncrypted []byte
var testRecordAlert []byte
var testRecordAppdata []byte

func init() {
	var loadFiles = []struct {
		vardata *[]byte
		binfile string
	}{
		{&testPacketClient, "fullpacket-client1.bin"},
		{&testPacketServer1, "fullpacket-server1.bin"},
		{&testPacketServer2, "fullpacket-server2.bin"},
		{&testRecordServerHello, "tlsr-hsk-serverhello1.bin"},
		{&testRecordCCS, "tlsr-ccs1.bin"},
		{&testRecordEncrypted, "tlsr-hsk-encrypted1.bin"},
		{&testRecordAlert, "tlsr-alert1.bin"},
		{&testRecordAppdata, "tlsr-appdata1.bin"},

		// {&testPacketClient, "tlsr1-fullpacket-client.bin"},
		// {&testPacketServer1, "tlsr1-fullpacket-server1.bin"},
		// {&testPacketServer2, "tlsr1-fullpacket-server2.bin"},
		// {&testRecordServerHello, "tlsr1-hsk-serverhello.bin"},
		// {&testRecordCCS, "tlsr1-ccs.bin"},
		// {&testRecordEncrypted, "tlsr1-hsk-encrypted.bin"},
		// {&testRecordAlert, "tlsr1-alert.bin"},
		// {&testRecordAppdata, "tlsr1-appdata.bin"},
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

func TestHasHeader(t *testing.T) {
	var header []byte

	header = testRecordServerHello
	if !HasHeader(header) {
		t.Error("Error checking tls header")
	}

	header = testRecordServerHello[0:4]
	if HasHeader(header) {
		t.Error("Error checking tls header")
	}

	header = testRecordServerHello[0:5]
	if !HasHeader(header) {
		t.Error("Error checking tls header")
	}

	header = testRecordServerHello[1:6]
	if HasHeader(header) {
		t.Error("Error checking tls header")
	}
}

func TestDecodeRecord(t *testing.T) {
	tlsrecord := &TLSRecord{}
	if err := tlsrecord.DecodeFromBytes(testRecordServerHello, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}
	if tlsrecord.Version != VersionTLS12 {
		t.Error("Invalid tls version")
	}

	if !tlsrecord.IsHandshake() {
		t.Error("Invalid type decoding")
	}

	if tlsrecord.IsAlert() {
		t.Error("Invalid type decoding")
	}

	if tlsrecord.IsApplicationData() {
		t.Error("Invalid type decoding")
	}

	if tlsrecord.IsChangeCipherSpec() {
		t.Error("Invalid type decoding")
	}

	if tlsrecord.Len != 89 {
		t.Error("Error getting MessageLen")
	}

	if len(tlsrecord.Payload()) != 89 {
		t.Error("Payload len is different from MessageLen")
	}

	if err := tlsrecord.DecodeFromBytes(testPacketClient, gopacket.NilDecodeFeedback); err != ErrTLSWrongContentType {
		t.Error("No error decoding full packet")
	}

	if err := tlsrecord.DecodeFromBytes(testRecordCCS, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	if !tlsrecord.IsChangeCipherSpec() {
		t.Error("Invalid type decoding")
	}

	if tlsrecord.Len != 1 {
		t.Error("Error getting MessageLen")
	}

	if err := tlsrecord.DecodeFromBytes(testRecordEncrypted, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	if !tlsrecord.IsHandshake() {
		t.Error("Invalid type decoding")
	}

	if err := tlsrecord.DecodeFromBytes(testRecordAlert, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	if !tlsrecord.IsAlert() {
		t.Error("Invalid type decoding")
	}

	if tlsrecord.Len != 26 {
		t.Error("Error getting MessageLen")
	}

	if err := tlsrecord.DecodeFromBytes(testRecordAppdata, gopacket.NilDecodeFeedback); err != nil {
		t.Error("No TLSRecord layer type found in byte slice")
	}

	if !tlsrecord.IsApplicationData() {
		t.Error("Invalid type decoding")
	}

	if tlsrecord.Len != 205 {
		t.Error("Error getting MessageLen")
	}

	if len(tlsrecord.Payload()) != 205 {
		t.Error("Error getting payload")
	}
}

func TestDecodePacket(t *testing.T) {
	p := gopacket.NewPacket(testPacketClient, layers.LinkTypeEthernet, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP, LayerTypeTLSRecord}, t)

	// Select the Application (TLSRecord) layer.
	pResultTLS, ok := p.ApplicationLayer().(*TLSRecord)
	if !ok {
		t.Error("No TLSRecord layer type found in packet")
	}
	if pResultTLS.IsHandshake() != true {
		t.Error("TLSRecord is not handshake: " + pResultTLS.Type.String())
	}
	if pResultTLS.Len != 512 {
		t.Error("TLSRecord ivalid message len")
	}
	if len(pResultTLS.Payload()) != 512 {
		t.Error("TLSRecord ivalid payload")
	}

	p = gopacket.NewPacket(testPacketServer1, layers.LinkTypeEthernet, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP, LayerTypeTLSRecord}, t)

	// Select the Application (TLSRecord) layer.
	pResultTLS, ok = p.ApplicationLayer().(*TLSRecord)
	if !ok {
		t.Error("No TLSRecord layer type found in packet")
	}
	if pResultTLS.IsHandshake() != true {
		t.Error("TLSRecord is not handshake: " + pResultTLS.Type.String())
	}
	if pResultTLS.Version != VersionTLS12 {
		t.Error("TLSRecord ivalid version")
	}
	if pResultTLS.Len != 89 {
		t.Error("TLSRecord ivalid message len")
	}
	if len(pResultTLS.Payload()) != 89 {
		t.Error("TLSRecord ivalid payload")
	}

}
