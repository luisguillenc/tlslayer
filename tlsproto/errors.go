// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import "errors"

// Some generic errors
var (
	ErrWrowngLenPayload     = errors.New("invalid len payload")
	ErrUnexpectedRecordType = errors.New("unexpected record type")
)

// common errors in alert
var (
	ErrAlertInvalidLevel = errors.New("unexpected alert level or is ciphered")
	ErrAlertInvalidDesc  = errors.New("unexpected alert description or is ciphered")
)

// common errors in CCS
var (
	ErrCCSInvalidValue = errors.New("unexpected change_cipher_spec value")
)

// common errors in handshake
var (
	ErrHandshakeWrongSize        = errors.New("handshake is of wrong size")
	ErrHandshakeWrongType        = errors.New("handshake is of wrong type")
	ErrHandshakeBadLength        = errors.New("handshake has a malformed length")
	ErrHandshakeExtBadLength     = errors.New("handshake extension has a malformed length")
	ErrHandshakePayloadMissmatch = errors.New("handshake payload missmatch")
	ErrHandshakeFragmented       = errors.New("handshake is fragmented in more than one tls record")
)

// common errors in certificates
var (
	ErrCertsBadLength      = errors.New("certificates has a malformed length")
	ErrCertsMissmatch      = errors.New("length of certificates missmatch")
	ErrCertsInvalidPayload = errors.New("length of certificate greater than payload")
)
