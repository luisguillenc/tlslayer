// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"

	"github.com/luisguillenc/tlslayer"
)

// AlertLevel defines de alert level in the alert protocol
type AlertLevel int8

// AlertDescription defines de alert description in the alert protocol
type AlertDescription int8

// Valid values of alert level
const (
	AlertLevelWarning AlertLevel = 1
	AlertLevelFatal   AlertLevel = 2
)

// Valid values of alert description
const (
	AlertCloseNotify            AlertDescription = 0
	AlertUnexpectedMessage      AlertDescription = 10
	AlertBadRecordMac           AlertDescription = 20
	AlertDecryptionFailed       AlertDescription = 21
	AlertRecordOverflow         AlertDescription = 22
	AlertDecompressionFailure   AlertDescription = 30
	AlertHandshakeFailure       AlertDescription = 40
	AlertNoCertificate          AlertDescription = 41
	AlertBadCertificate         AlertDescription = 42
	AlertUnsupportedCertificate AlertDescription = 43
	AlertCertificateRevoked     AlertDescription = 44
	AlertCertificateExpired     AlertDescription = 45
	AlertCertificateUnknown     AlertDescription = 46
	AlertIllegalParameter       AlertDescription = 47
	AlertUnknownCa              AlertDescription = 48
	AlertAccessDenied           AlertDescription = 49
	AlertDecodeError            AlertDescription = 50
	AlertDecryptError           AlertDescription = 51
	AlertExportRestriction      AlertDescription = 60
	AlertProtocolVersion        AlertDescription = 70
	AlertInsufficientSecurity   AlertDescription = 71
	AlertInternalError          AlertDescription = 80
	AlertUserCanceled           AlertDescription = 90
	AlertNoRenegotiation        AlertDescription = 100
	AlertUnSupportedExtension   AlertDescription = 110
)

// alertDescriptionReg is a map with strings of alert description
var alertDescriptionReg = map[AlertDescription]string{
	AlertCloseNotify:            "close_notify",
	AlertUnexpectedMessage:      "unexpected_message",
	AlertBadRecordMac:           "bad_record_mac",
	AlertDecryptionFailed:       "decryption_failed_RESERVED",
	AlertRecordOverflow:         "record_overflow",
	AlertDecompressionFailure:   "decompression_failure",
	AlertHandshakeFailure:       "handshake_failure",
	AlertNoCertificate:          "no_certificate_RESERVED",
	AlertBadCertificate:         "bad_certificate",
	AlertUnsupportedCertificate: "unsupported_certificate",
	AlertCertificateRevoked:     "certificate_revoked",
	AlertCertificateExpired:     "certificate_expired",
	AlertCertificateUnknown:     "certificate_unknown",
	AlertIllegalParameter:       "illegal_parameter",
	AlertUnknownCa:              "unknown_ca",
	AlertAccessDenied:           "access_denied",
	AlertDecodeError:            "decode_error",
	AlertDecryptError:           "decrypt_error",
	AlertExportRestriction:      "export_restriction_RESERVED",
	AlertProtocolVersion:        "protocol_version",
	AlertInsufficientSecurity:   "insufficient_security",
	AlertInternalError:          "internal_error",
	AlertUserCanceled:           "user_canceled",
	AlertNoRenegotiation:        "no_renegotiation",
	AlertUnSupportedExtension:   "unsupported_extension",
}

func (l AlertLevel) getDesc() string {
	if l == AlertLevelWarning {
		return "warning"
	} else if l == AlertLevelFatal {
		return "fatal"
	} else {
		return "unknown"
	}
}

func (l AlertLevel) String() string {
	return fmt.Sprintf("%s(%d)", l.getDesc(), l)
}

// IsValid method checks if it's a valid value
func (l AlertLevel) IsValid() bool {
	return (l == AlertLevelWarning) || (l == AlertLevelFatal)
}

func (d AlertDescription) getDesc() string {
	if name, ok := alertDescriptionReg[d]; ok {
		return name
	}
	return "unknown"
}

func (d AlertDescription) String() string {
	return fmt.Sprintf("%s(%d)", d.getDesc(), d)
}

// IsValid method checks if it's a valid value
func (d AlertDescription) IsValid() bool {
	_, ok := alertDescriptionReg[d]
	return ok
}

// Alert is the struct for tls messages of alert protocol
type Alert struct {
	TLSMessage

	Level       AlertLevel       `json:"level"`
	Description AlertDescription `json:"description"`
}

func (alert *Alert) String() string {
	str := fmt.Sprint(alert.Level, ",", alert.Description)

	return str
}

// GetContentType returns the content type
func (alert *Alert) GetContentType() tlslayer.ContentType {
	return tlslayer.ContentTypeAlert
}

// NewAlertFromBytes creates an alert from a byte slice with the payload
func NewAlertFromBytes(payload []byte) (*Alert, error) {
	if len(payload) < 2 {
		return nil, ErrWrowngLenPayload
	}

	level := AlertLevel(payload[0])
	if !level.IsValid() {
		return nil, ErrAlertInvalidLevel
	}
	description := AlertDescription(payload[1])
	if !description.IsValid() {
		return nil, ErrAlertInvalidDesc
	}
	alert := &Alert{Level: level, Description: description}

	return alert, nil
}

// NewAlertFromRecord creates an alert from a TLS Record
func NewAlertFromRecord(tlsr *tlslayer.TLSRecord) (*Alert, error) {
	if tlsr.Type != tlslayer.ContentTypeAlert {
		return nil, ErrUnexpectedRecordType
	}
	if len(tlsr.Payload()) != 2 {
		return nil, ErrWrowngLenPayload
	}
	return NewAlertFromBytes(tlsr.Payload())
}
