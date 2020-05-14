// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"crypto/x509"
	"fmt"
)

// CertificateData is the struct for protocol hanshake message Certificate
type CertificateData struct {
	CertificatesLen uint32              `json:"certificatesLen"`
	Certificates    []*x509.Certificate `json:"certificates,omitempty"`
}

func (hs *CertificateData) String() string {
	str := fmt.Sprintln("Certificates Len:", hs.CertificatesLen)

	return str
}

func decodeHskCertificate(hsk *Handshake, payload []byte) error {
	// Get certificateslen
	if len(payload) < 3 {
		return ErrCertsBadLength
	}
	// new certdata
	certData := &CertificateData{}
	certData.CertificatesLen = uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])
	payload = payload[3:]

	//checklen
	if len(payload) != int(certData.CertificatesLen) {
		return ErrCertsMissmatch
	}
	// get certificates
	for len(payload) > 0 {
		certLen := uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])
		if len(payload) < int(certLen) {
			return ErrCertsInvalidPayload
		}
		certificate := payload[3 : 3+certLen]
		asnCert, err := x509.ParseCertificate(certificate)
		if err != nil {
			return err
		}
		certData.Certificates = append(certData.Certificates, asnCert)
		// next certificate
		payload = payload[3+certLen:]
	}

	hsk.Certificate = certData
	return nil
}
