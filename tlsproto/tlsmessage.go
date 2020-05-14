// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package tlsproto

import (
	"github.com/luisguillenc/tlslayer"
)

// TLSMessage is an interface of type ContentType
type TLSMessage interface {
	GetContentType() tlslayer.ContentType
	String() string
}
