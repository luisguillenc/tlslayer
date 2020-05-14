// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"fmt"
)

// Extension stores extension information
type Extension struct {
	Type    ExtensionType `json:"type"`
	Len     uint16        `json:"len"`
	payload []byte
}

// ExtensionsInfo stores all decoded information from extensions
type ExtensionsInfo struct {
	// ExtServerName
	SNI string `json:"sni,omitempty"`
	// ExtSignatureAlgs
	SignatureSchemes []SignatureScheme `json:"signatureSchemes,omitempty"`
	// ExtSupportedVersions
	SupportedVersions []SupportedVersion `json:"supportedVersions,omitempty"`
	// ExtSupportedGroups
	SupportedGroups []SupportedGroup `json:"supportedGroups,omitempty"`
	// ExtECPointFormats
	ECPointFormats []ECPointFormat `json:"ecPointFormats,omitempty"`
	// ExtStatusRequest
	OSCP bool `json:"oscp"`
	// ExtALPN
	ALPNs []string `json:"alpns,omitempty"`
	// ExtKeyShare
	KeyShareEntries []KeyShareEntry `json:"keyShareEntries,omitempty"`
	// ExtPSKKeyExchangeModes
	PSKKeyExchangeModes []PSKKeyExchangeMode `json:"pskKeyExchangeModes,omitempty"`
}

// ExtensionType is an extension type defined by rfc
type ExtensionType uint16

// TLS Extensions http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const (
	ExtServerName           ExtensionType = 0
	ExtMaxFragLen           ExtensionType = 1
	ExtClientCertURL        ExtensionType = 2
	ExtTrustedCAKeys        ExtensionType = 3
	ExtTruncatedHMAC        ExtensionType = 4
	ExtStatusRequest        ExtensionType = 5
	ExtUserMapping          ExtensionType = 6
	ExtClientAuthz          ExtensionType = 7
	ExtServerAuthz          ExtensionType = 8
	ExtCertType             ExtensionType = 9
	ExtSupportedGroups      ExtensionType = 10
	ExtECPointFormats       ExtensionType = 11
	ExtSRP                  ExtensionType = 12
	ExtSignatureAlgs        ExtensionType = 13
	ExtUseSRTP              ExtensionType = 14
	ExtHeartbeat            ExtensionType = 15
	ExtALPN                 ExtensionType = 16 // Replaced NPN
	ExtStatusRequestV2      ExtensionType = 17
	ExtSignedCertTS         ExtensionType = 18 // Certificate Transparency
	ExtClientCertType       ExtensionType = 19
	ExtServerCertType       ExtensionType = 20
	ExtPadding              ExtensionType = 21 // Temp http://www.iana.org/go/draft-ietf-tls-padding
	ExtEncryptThenMAC       ExtensionType = 22
	ExtExtendedMasterSecret ExtensionType = 23
	ExtTokenBinding         ExtensionType = 24
	ExtCachedInfo           ExtensionType = 25
	ExtCompressCert         ExtensionType = 27
	ExtRecordSizeLimit      ExtensionType = 28
	ExtPwdProtect           ExtensionType = 29
	ExtPwdClear             ExtensionType = 30
	ExtPasswordSalt         ExtensionType = 31
	ExtSessionTicket        ExtensionType = 35
	ExtPreSharedKey         ExtensionType = 41
	ExtEarlyData            ExtensionType = 42
	ExtSupportedVersions    ExtensionType = 43
	ExtCookie               ExtensionType = 44
	ExtPSKKeyExchangeModes  ExtensionType = 45
	ExtCertAuthorities      ExtensionType = 47
	ExtOIDFilters           ExtensionType = 48
	ExtPostHandshakeAuth    ExtensionType = 49
	ExtSignatureAlgsCert    ExtensionType = 50
	ExtKeyShare             ExtensionType = 51
	ExtNPN                  ExtensionType = 13172 // Next Protocol Negotiation not ratified and replaced by ALPN
	ExtRenegotiationInfo    ExtensionType = 65281
)

// decodeExt is a function that puts decoded data from an extension into an info struct
type decodeExt func(info *ExtensionsInfo, ht HandshakeType, data []byte) error

var extensionReg = map[ExtensionType]struct {
	desc    string
	decoder decodeExt
}{
	ExtServerName:           {"server_name", decodeExtServerName},
	ExtMaxFragLen:           {"max_fragment_length", nil},
	ExtClientCertURL:        {"client_certificate_url", nil},
	ExtTrustedCAKeys:        {"trusted_ca_keys", nil},
	ExtTruncatedHMAC:        {"truncated_hmac", nil},
	ExtStatusRequest:        {"status_request", decodeExtStatusRequest},
	ExtUserMapping:          {"user_mapping", nil},
	ExtClientAuthz:          {"client_authz", nil},
	ExtServerAuthz:          {"server_authz", nil},
	ExtCertType:             {"cert_type", nil},
	ExtSupportedGroups:      {"supported_groups", decodeExtSupportedGroups},
	ExtECPointFormats:       {"ec_point_formats", decodeExtECPointFormats},
	ExtSRP:                  {"srp", nil},
	ExtSignatureAlgs:        {"signature_algorithms", decodeExtSignatureAlgs},
	ExtUseSRTP:              {"use_srtp", nil},
	ExtHeartbeat:            {"heartbeat", nil},
	ExtALPN:                 {"application_layer_protocol_negotiation", decodeExtALPN},
	ExtStatusRequestV2:      {"status_request_v2", nil},
	ExtSignedCertTS:         {"signed_certificate_timestamp", nil},
	ExtClientCertType:       {"client_certificate_type", nil},
	ExtServerCertType:       {"server_certificate_type", nil},
	ExtPadding:              {"padding", nil},
	ExtEncryptThenMAC:       {"encrypt_then_mac", nil},
	ExtExtendedMasterSecret: {"extended_master_secret", nil},
	ExtTokenBinding:         {"token_binding", nil},
	ExtCachedInfo:           {"cached_info", nil},
	ExtCompressCert:         {"compress_certificate ", nil},
	ExtRecordSizeLimit:      {"record_size_limit", nil},
	ExtPwdProtect:           {"pwd_protect", nil},
	ExtPwdClear:             {"pwd_clear", nil},
	ExtPasswordSalt:         {"password_salt", nil},
	ExtSessionTicket:        {"session_ticket", nil},
	ExtPreSharedKey:         {"pre_shared_key", nil},
	ExtEarlyData:            {"early_data", nil},
	ExtSupportedVersions:    {"supported_versions", decodeExtSupportedVersions},
	ExtCookie:               {"cookie", nil},
	ExtPSKKeyExchangeModes:  {"psk_key_exchange_modes", decodeExtPSKKeyExchangeModes},
	ExtCertAuthorities:      {"certificate_authorities", nil},
	ExtOIDFilters:           {"oid_filters", nil},
	ExtPostHandshakeAuth:    {"post_handshake_auth", nil},
	ExtSignatureAlgsCert:    {"signature_algorithms_cert", nil},
	ExtKeyShare:             {"key_share", decodeExtKeyShare},
	ExtNPN:                  {"next_protocol_negotiation", nil},
	ExtRenegotiationInfo:    {"renegotiation_info", nil},
}

func (e ExtensionType) getDesc() string {
	if ext, ok := extensionReg[e]; ok {
		return ext.desc
	}
	if e.IsGREASE() {
		return "GREASE"
	}
	return "unknown"
}

// String method for a TLS Extension
func (e ExtensionType) String() string {
	return fmt.Sprintf("%s(%d)", e.getDesc(), e)
}

// IsGREASE returns true if is an extension reserved by GREASE rfc
func (e ExtensionType) IsGREASE() bool {
	return isGREASE16(uint16(e))
}

func (e Extension) String() string {
	return fmt.Sprintf("%s (len=%d)", e.Type, e.Len)
}

func (i *ExtensionsInfo) String() string {
	str := fmt.Sprintf("SNI: %q\n", i.SNI)
	str += fmt.Sprintf("Signature Schemes: %v\n", i.SignatureSchemes)
	str += fmt.Sprintf("Supported Groups: %v\n", i.SupportedGroups)
	str += fmt.Sprintf("ECPoints Formats: %v\n", i.ECPointFormats)
	str += fmt.Sprintf("OSCP: %v\n", i.OSCP)
	str += fmt.Sprintf("ALPNs: %v", i.ALPNs)
	str += fmt.Sprintf("Supported Versions: %v\n", i.SupportedVersions)
	str += fmt.Sprintf("Key Share Entries: %v\n", i.KeyShareEntries)
	str += fmt.Sprintf("PSK Key Exchange Modes: %v\n", i.PSKKeyExchangeModes)

	return str
}

const extensionsCap = 16

// getExtensionsFromBytes returns array with extension types and payloads
func getExtensionsFromBytes(payload []byte) ([]Extension, error) {
	extensions := make([]Extension, 0, extensionsCap)
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, ErrHandshakeExtBadLength
		}
		extType := ExtensionType(payload[0])<<8 | ExtensionType(payload[1])
		length := uint16(payload[2])<<8 | uint16(payload[3])

		// get data
		if len(payload) < 4+int(length) {
			return nil, ErrHandshakeExtBadLength
		}
		data := payload[4 : 4+length]

		// add extension type and bytes
		extension := Extension{Type: extType, Len: length, payload: data}
		extensions = append(extensions, extension)

		// forward to next extension
		payload = payload[4+length:]
	}
	return extensions, nil
}

// getExtensionsInfo process array with extensions and decodes its information into an ExtensionsInfo struct
func getExtensionsInfo(ht HandshakeType, extensions []Extension) (*ExtensionsInfo, error) {
	info := &ExtensionsInfo{}
	for _, extension := range extensions {
		if ext, ok := extensionReg[extension.Type]; ok {
			if ext.decoder == nil {
				continue
			}
			err := ext.decoder(info, ht, extension.payload)
			if err != nil {
				return info, err
			}
		}
	}
	return info, nil
}
