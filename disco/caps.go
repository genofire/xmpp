// Copyright 2021 The Mellium Contributors.
// Use of this source code is governed by the BSD 2-clause
// license that can be found in the LICENSE file.

package disco

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
	"sort"
	"sync"

	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/form"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"
)

// CapsHandler handles incoming entity capabilities by checking if the entity
// has service discovery information in the cache and requesting it if not.
type CapsHandler struct {
	cacheM sync.Mutex
	cache  map[string]Info

	// Session is the session on which we want to send service discovery requests
	// for hashes that are not in the cache.
	// Normally this should be the same session on which the handler is
	// registered.
	Session *xmpp.Session

	// BaseContext optionally specifies a function that returns the base context
	// for incoming requests on this server.
	// The provided JID is the one that we will be requesting service discovery
	// info from.
	// If BaseContext is nil, the default is context.Background().
	// If non-nil, it must return a non-nil context.
	BaseContext func(j jid.JID) context.Context
}

// HandlePresence implements stanza.PresenceHandler.
func (h *CapsHandler) HandlePresence(p stanza.Presence, e xmlstream.TokenReadEncoder) error {
	iter := xmlstream.NewIter(e)
	var c Caps
	for iter.Next() {
		start, r := iter.Current()
		if start.Name.Local == "c" && start.Name.Space == NSCaps {
			d := xml.NewTokenDecoder(xmlstream.MultiReader(xmlstream.Token(start), r))
			err := d.Decode(&c)
			if err != nil {
				return err
			}
			break
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	h.cacheM.Lock()
	defer h.cacheM.Unlock()
	key := c.Node + "#" + c.Ver
	_, ok := h.cache[key]
	if ok {
		return nil
	}
	ctx := context.Background()
	if h.BaseContext != nil {
		ctx = h.BaseContext(p.From)
	}
	info, err := GetInfo(ctx, key, p.From, h.Session)
	if err != nil {
		return err
	}
	// TODO: hash ourself. If it does not match, apply to this JID only or ignore?
	h.cache[key] = info
	return nil
}

// Caps can be included in a presence stanza or in stream features to advertise
// entity capabilities.
// Node is a string that uniquely identifies your client (eg.
// https://example.com/myclient) and ver is the hash of an Info value.
type Caps struct {
	XMLName xml.Name    `xml:"http://jabber.org/protocol/caps c"`
	Hash    crypto.Hash `xml:"hash,attr"`
	Node    string      `xml:"node,attr"`
	Ver     string      `xml:"ver,attr"`
}

// Hash generates the entity capabilities verification string.
// Its output is suitable for use as a cache key.
func (i Info) Hash(h hash.Hash) string {
	return string(i.AppendHash(nil, h))
}

// AppendHash is like Hash except that it appends the output string to the
// provided byte slice.
func (i Info) AppendHash(dst []byte, h hash.Hash) []byte {
	// Hash identities
	// TODO: does this match RFC 4790 § 9.3?
	sort.Slice(i.Identity, func(a, b int) bool {
		identI, identJ := i.Identity[a], i.Identity[b]
		if identI.Category != identJ.Category {
			return identI.Category < identJ.Category
		}
		if identI.Type != identJ.Type {
			return identI.Type < identJ.Type
		}
		if identI.Lang != identJ.Lang {
			return identI.Lang < identJ.Lang
		}
		return false
	})
	for _, ident := range i.Identity {
		/* #nosec */
		fmt.Fprintf(h, "%s/%s/%s/%s<", ident.Category, ident.Type, ident.Lang, ident.Name)
	}

	// Hash features
	sort.Slice(i.Features, func(a, b int) bool {
		return i.Features[a].Var < i.Features[b].Var
	})
	for _, f := range i.Features {
		/* #nosec */
		io.WriteString(h, f.Var)
		/* #nosec */
		io.WriteString(h, "<")
	}

	// Hash forms
	for _, infoForm := range i.Form {
		var formType string
		fields := make([]string, 0, infoForm.Len()-1)
		infoForm.ForFields(func(f form.FieldData) {
			if f.Var == "FORM_TYPE" {
				formType, _ = infoForm.GetString("FORM_TYPE")
				return
			}
			fields = append(fields, f.Var)
		})
		sort.Strings(fields)
		/* #nosec */
		io.WriteString(h, formType)
		/* #nosec */
		io.WriteString(h, "<")
		for _, f := range fields {
			/* #nosec */
			io.WriteString(h, f)
			/* #nosec */
			io.WriteString(h, "<")
			vals, _ := infoForm.Raw(f)
			sort.Strings(vals)
			for _, val := range vals {
				/* #nosec */
				io.WriteString(h, val)
				/* #nosec */
				io.WriteString(h, "<")
			}
		}
	}

	dst = h.Sum(dst)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(dst)))
	base64.StdEncoding.Encode(out, dst)
	return out
}
