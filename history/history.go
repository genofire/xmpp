// Copyright 2021 The Mellium Contributors.
// Use of this source code is governed by the BSD 2-clause
// license that can be found in the LICENSE file.

package history

import (
	"context"
	"encoding/xml"

	"mellium.im/xmpp"
	"mellium.im/xmpp/internal/attr"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/mux"
	"mellium.im/xmpp/paging"
	"mellium.im/xmpp/stanza"
)

// Handle returns an option that registers a Handler for incoming history query
// results.
func Handle(h mux.MessageHandler) mux.Option {
	return mux.Message("", xml.Name{Space: NS, Local: "result"}, h)
}

// Fetch requests messages from the archive.
// The messages must be handled separately and Fetch blocks until they have all
// been prosessed.
func Fetch(ctx context.Context, filter Query, to jid.JID, s *xmpp.Session) (paging.Set, error) {
	return FetchIQ(ctx, filter, stanza.IQ{
		To: to,
	}, s)
}

// FetchIQ is like fetch but it allows modifying the underlying IQ.
// Changing the type of the IQ has no effect.
func FetchIQ(ctx context.Context, filter Query, iq stanza.IQ, s *xmpp.Session) (paging.Set, error) {
	if filter.ID == "" {
		filter.ID = attr.RandomID()
	}
	iq.Type = stanza.SetIQ
	var result struct {
		XMLName xml.Name `xml:"urn:xmpp:mam:2 fin"`
		Set     paging.Set
	}
	err := s.UnmarshalIQ(
		ctx,
		iq.Wrap(filter.TokenReader()),
		&result,
	)
	return result.Set, err
}
