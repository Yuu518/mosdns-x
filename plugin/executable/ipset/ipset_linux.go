//go:build linux

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

package ipset

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

var _ coremain.ExecutablePlugin = (*ipsetPlugin)(nil)

type ipsetPlugin struct {
	*coremain.BP
	args *Args
	sock *nl.NetlinkSocket
	socks map[int]*nl.SocketHandle
}

func newIpsetPlugin(bp *coremain.BP, args *Args) (*ipsetPlugin, error) {
	if args.Mask4 == 0 {
		args.Mask4 = 24
	}
	if args.Mask6 == 0 {
		args.Mask6 = 32
	}

	sock, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}

	return &ipsetPlugin{
		BP:    bp,
		args:  args,
		sock:  sock,
		socks: map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: {Socket: sock}},
	}, nil
}

func (p *ipsetPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	r := qCtx.R()
	if r != nil {
		er := p.addIPSet(r)
		if er != nil {
			p.L().Warn("failed to add response IP to ipset", qCtx.InfoField(), zap.Error(er))
		}
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *ipsetPlugin) Close() error {
	p.sock.Close()
	return nil
}

func (p *ipsetPlugin) addPrefix(setName string, prefix netip.Prefix) error {
	addr := prefix.Addr()
	addrType := nl.IPSET_ATTR_IPADDR_IPV6
	if addr.Is4() {
		addrType = nl.IPSET_ATTR_IPADDR_IPV4
	}

	req := nl.NewNetlinkRequest(nl.IPSET_CMD_ADD|(unix.NFNL_SUBSYS_IPSET<<8), unix.NLM_F_ACK)
	req.Sockets = p.socks
	req.AddData(&nl.Nfgenmsg{NfgenFamily: unix.AF_INET, Version: nl.NFNETLINK_V0})
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_PROTOCOL, nl.Uint8Attr(nl.IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(nl.IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))

	data := nl.NewRtAttr(nl.IPSET_ATTR_DATA|int(nl.NLA_F_NESTED), nil)
	ip := nl.NewRtAttr(addrType|int(nl.NLA_F_NET_BYTEORDER), addr.AsSlice())
	data.AddChild(nl.NewRtAttr(nl.IPSET_ATTR_IP|int(nl.NLA_F_NESTED), ip.Serialize()))
	data.AddChild(nl.NewRtAttr(nl.IPSET_ATTR_CIDR, nl.Uint8Attr(uint8(prefix.Bits()))))
	data.AddChild(&nl.Uint32Attribute{Type: nl.IPSET_ATTR_LINENO | nl.NLA_F_NET_BYTEORDER, Value: 0})
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	var errno syscall.Errno
	if errors.As(err, &errno) && errno >= nl.IPSET_ERR_PRIVATE {
		return fmt.Errorf("ipset %s: %w", setName, nl.IPSetError(errno))
	}
	return err
}

func (p *ipsetPlugin) addIPSet(r *dns.Msg) error {
	for i := range r.Answer {
		switch rr := r.Answer[i].(type) {
		case *dns.A:
			if len(p.args.SetName4) == 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(rr.A.To4())
			if !ok {
				return fmt.Errorf("invalid A record with ip: %s", rr.A)
			}
			if err := p.addPrefix(p.args.SetName4, netip.PrefixFrom(addr, p.args.Mask4)); err != nil {
				return err
			}

		case *dns.AAAA:
			if len(p.args.SetName6) == 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(rr.AAAA.To16())
			if !ok {
				return fmt.Errorf("invalid AAAA record with ip: %s", rr.AAAA)
			}
			if err := p.addPrefix(p.args.SetName6, netip.PrefixFrom(addr, p.args.Mask6)); err != nil {
				return err
			}
		default:
			continue
		}
	}

	return nil
}
