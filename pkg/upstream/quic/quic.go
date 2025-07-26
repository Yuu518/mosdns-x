/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

type Upstream struct {
	conn       *quic.Conn
	addr       string
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	connLock   sync.Mutex
	qConfLock  sync.Mutex
}

func NewQUICUpstream(addr string, tlsConfig *tls.Config, quicConfig *quic.Config) *Upstream {
	return &Upstream{
		addr:       addr,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		connLock:   sync.Mutex{},
		qConfLock:  sync.Mutex{},
	}
}

func (h *Upstream) getQuicConfig() *quic.Config {
	h.qConfLock.Lock()
	defer h.qConfLock.Unlock()
	return h.quicConfig
}

func (h *Upstream) resetQuicConfig() {
	h.qConfLock.Lock()
	defer h.qConfLock.Unlock()
	config := h.quicConfig.Clone()
	config.TokenStore = quic.NewLRUTokenStore(1, 10)
	h.quicConfig = config
}

func (h *Upstream) offer(ctx context.Context) (*quic.Conn, bool, error) {
	h.connLock.Lock()
	defer h.connLock.Unlock()
	conn := h.conn
	if conn != nil {
		return conn, true, nil
	}
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "udp", h.addr)
	if err != nil {
		return nil, false, err
	}
	rawConn.Close()
	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return nil, false, fmt.Errorf("unexpected type %T", rawConn)
	}
	conn, err = quic.DialAddrEarly(ctx, udpConn.RemoteAddr().String(), h.tlsConfig.Clone(), h.getQuicConfig())
	if err != nil {
		return nil, false, err
	}
	h.conn = conn
	return conn, false, nil
}

func (h *Upstream) Close() error {
	h.connLock.Lock()
	defer h.connLock.Unlock()
	conn := h.conn
	if conn != nil {
		go conn.CloseWithError(0, "")
		h.conn = nil
	}
	return nil
}

func (h *Upstream) closeWithError(conn *quic.Conn, err error) {
	h.connLock.Lock()
	defer h.connLock.Unlock()
	if err == nil {
		go conn.CloseWithError(0, "")
	} else {
		go conn.CloseWithError(1, "")
	}
	if errors.Is(err, quic.Err0RTTRejected) {
		h.resetQuicConfig()
	}
	if conn == h.conn {
		h.conn = nil
	}
}

func (h *Upstream) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	conn, cached, err := h.offer(ctx)
	if err != nil {
		return nil, err
	}
	m.Id = 0
	resp, err := exchangeMsg(ctx, conn, m)
	if err != nil && cached {
		h.closeWithError(conn, err)
		conn, _, err = h.offer(ctx)
		if err != nil {
			return nil, err
		}
		resp, err = exchangeMsg(ctx, conn, m)
	}
	if err != nil {
		h.closeWithError(conn, err)
		return nil, err
	}
	return resp, nil
}

func exchangeMsg(ctx context.Context, conn *quic.Conn, m *dns.Msg) (*dns.Msg, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	_, err = dnsutils.WriteMsgToTCP(stream, m)
	if err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return nil, err
	}
	stream.Close()
	resp, _, err := dnsutils.ReadMsgFromTCP(stream)
	if err != nil {
		stream.CancelRead(1)
		return nil, err
	}
	return resp, nil
}
