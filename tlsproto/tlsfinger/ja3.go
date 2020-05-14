// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsfinger

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/luisguillenc/tlslayer/tlsproto"
)

// GetJA3 returns fingerprint in JA3 format https://github.com/salesforce/ja3
func GetJA3(ch *tlsproto.ClientHelloData) (string, string) {

	fprint := strconv.Itoa(int(ch.ClientVersion))

	suites := ""
	for _, c := range ch.CipherSuites {
		if c.IsGREASE() {
			continue
		}
		if suites != "" {
			suites = suites + "-"
		}
		suites = suites + strconv.Itoa(int(c))
	}
	fprint = fprint + "," + suites

	extensions := ""
	for _, e := range ch.Extensions {
		if e.Type.IsGREASE() {
			continue
		}
		if extensions != "" {
			extensions = extensions + "-"
		}
		extensions = extensions + strconv.Itoa(int(e.Type))
	}
	fprint = fprint + "," + extensions

	elliptic := ""
	if ch.ExtInfo.SupportedGroups != nil {
		for _, sg := range ch.ExtInfo.SupportedGroups {
			if sg.IsGREASE() {
				continue
			}
			if elliptic != "" {
				elliptic = elliptic + "-"
			}
			elliptic = elliptic + strconv.Itoa(int(sg))
		}
	}
	fprint = fprint + "," + elliptic

	pointf := ""
	if ch.ExtInfo.ECPointFormats != nil {
		for _, pf := range ch.ExtInfo.ECPointFormats {
			if pointf != "" {
				pointf = pointf + "-"
			}
			pointf = pointf + strconv.Itoa(int(pf))
		}
	}
	fprint = fprint + "," + pointf

	return fprint, hashString(fprint)
}

func hashString(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
