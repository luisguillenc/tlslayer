// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.
package tlsfinger

import (
	"bufio"
	"os"
	"testing"

	"github.com/google/gopacket"

	"github.com/luisguillenc/tlslayer"
	"github.com/luisguillenc/tlslayer/tlsproto"
)

const (
	pathBinFiles = "../../test/captures"
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

var testRecordClientHello1 []byte
var testRecordGREASE []byte

func init() {
	var loadFiles = []struct {
		vardata *[]byte
		binfile string
	}{
		{&testRecordClientHello1, "tlsr1-hsk-clienthello.bin"},
		{&testRecordGREASE, "tlsr1-hsk-clienthello-grease.bin"},
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

func TestFingerClientHello1(t *testing.T) {
	handshake, err := tlsproto.NewHandshakeFromBytes(testRecordClientHello1[5:])
	if err != nil {
		t.Fatal("getting handshake from record:", err)
	}
	if handshake.GetType() != tlslayer.ContentTypeHandshake {
		t.Fatalf("expected type: %v, got: %v", tlslayer.ContentTypeHandshake, handshake.GetType())
	}

	if handshake.Type != tlsproto.HandshakeTypeClientHello {
		t.Errorf("expected handshake type: %v, got: %v", tlsproto.HandshakeTypeClientHello, handshake.Type)
	}

	expected := "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-21,29-23-24-25-256-257,0"
	finger, digest := GetJA3(handshake.ClientHello)
	if finger != expected {
		t.Errorf("expected fingerprint: %v, got %v", expected, finger)
	}

	if digest != "7375c86ede5d928ba34a0622e4ac0dcd" {
		t.Errorf("expected digest: 7375c86ede5d928ba34a0622e4ac0dcd, got %v", digest)
	}
}

func TestFingerClientHelloGREASE(t *testing.T) {
	handshake, err := tlsproto.NewHandshakeFromBytes(testRecordGREASE[5:])
	if err != nil {
		t.Fatal("getting handshake from record:", err)
	}
	if handshake.GetType() != tlslayer.ContentTypeHandshake {
		t.Fatalf("expected type: %v, got: %v", tlslayer.ContentTypeHandshake, handshake.GetType())
	}

	if handshake.Type != tlsproto.HandshakeTypeClientHello {
		t.Errorf("expected handshake type: %v, got: %v", tlsproto.HandshakeTypeClientHello, handshake.Type)
	}

	expected := "771,52393-52392-49195-49199-49196-49200-49171-49172-156-157-47-53-10,65281-0-23-35-13-5-18-16-30032-11-10-21,29-23-24,0"
	finger, digest := GetJA3(handshake.ClientHello)
	if finger != expected {
		t.Errorf("expected fingerprint: %v, got %v", expected, finger)
	}

	if digest != "46efd49abcca8ea9baa932da68fdb529" {
		t.Errorf("expected digest: 46efd49abcca8ea9baa932da68fdb529, got %v", digest)
	}
}
