// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"

	"github.com/luisguillenc/tlslayer"
)

// ApplicationData is the struct for tls messages of application protocol
type ApplicationData struct {
	TLSMessage

	Data []byte `json:"data,omitempty"`
}

func (appdata *ApplicationData) String() string {
	return fmt.Sprintf("(len=%d)", len(appdata.Data))
}

// GetType returns the content type
func (appdata *ApplicationData) GetType() tlslayer.ContentType {
	return tlslayer.ContentTypeApplicationData
}

// NewApplicationDataFromBytes creates an alert from a byte slice with the payload
func NewApplicationDataFromBytes(payload []byte) (*ApplicationData, error) {
	appdata := &ApplicationData{Data: payload}

	return appdata, nil
}

// NewApplicationDataFromRecord creates an application data from a TLS Record
func NewApplicationDataFromRecord(tlsr *tlslayer.TLSRecord) (*ApplicationData, error) {
	if tlsr.Type != tlslayer.ContentTypeApplicationData {
		return nil, ErrUnexpectedRecordType
	}

	return NewApplicationDataFromBytes(tlsr.Payload())
}
