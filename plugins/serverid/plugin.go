// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// This plugin tells the client our server ID and then, on subsequent
// requests, verifies that the client has sent back our server ID.

// Clients may send messages to multiple servers by direct broadcast.
// Relays may also forward client messages to multiple servers.
// In either case, a client will receive responses from multiple
// servers and the client will choose one server. This plugin ensures
// that the unchosen servers drop subsequent messages that
// the client intends to send to the chosen one.

// Since this plugin drops packets intended for other servers, it should
// be the first plugin in the configuration. An earlier plugin might
// change state (e.g. record a lease) for a message that shouldn't be
// processed.

// Every coredhcp server should use this plugin. Even if you only run
// one DHCP server, you never know when some new device might start
// providing a rogue DHCP service. The log messages from this plugin
// may be your first indication that has happened. Also, this plugin is
// required for RFC 8415-compliant DHCPv6 behavior, and without a
// serverid, a DHCPv4 client cannot send renewal or release messages.

// The DHCPv4 plugin optionally accepts a list of RFC 5107 server
// identififer overrides that it should accept. It ignores any
// overrides that are not on the list. An override provided by a
// DHCPv4 relay agent is usually the IP address of the relay agent
// itself, and is typically used to cause the client to send (unicast)
// renewal and release messages via the relay agent instead of directly
// to the server.

// Note that DHCPv4 relay agents which provide a server identifier
// override must send client requests to only one DHCP server, because
// the serverid no longer distinguishes between responding servers.

// When at least one override is on the list to accept, the DHCPv4
// serverid itself may be configured as the string "override_only".
// This causes us to drop any DHCPv4 messages not received from
// a relay agent providing an authorized override.

package serverid

import (
	"errors"
	"net"
	"strings"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

var log = logger.GetLogger("plugins/server_id")

// Plugin wraps plugin registration information
var Plugin = plugins.Plugin{
	Name:   "server_id",
	Setup6: setup6,
	Setup4: setup4,
}

// v6ServerID is the DUID of the v6 server
var (
	v6ServerID  *dhcpv6.Duid
	v4ServerID  net.IP
	v4Overrides []net.IP
)

// Handler6 handles DHCPv6 packets for the server_id plugin.
func Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	if v6ServerID == nil {
		log.Fatal("BUG: Plugin is running uninitialized!")
		return nil, true
	}

	msg, err := req.GetInnerMessage()
	if err != nil {
		// BUG: this should already have failed in the main handler. Abort
		log.Error(err)
		return nil, true
	}

	if sid := msg.Options.ServerID(); sid != nil {
		// RFC8415 §16.{2,5,7}
		// These message types MUST be discarded if they contain *any* ServerID option
		if msg.MessageType == dhcpv6.MessageTypeSolicit ||
			msg.MessageType == dhcpv6.MessageTypeConfirm ||
			msg.MessageType == dhcpv6.MessageTypeRebind {
			log.Debug("prohibited server ID is present, dropping")
			return nil, true
		}

		// Approximately all others MUST be discarded if the ServerID doesn't match
		if !sid.Equal(*v6ServerID) {
			log.Infof("request server ID %v does not match ours %v, dropping", sid, *v6ServerID)
			return nil, true
		}
	} else if msg.MessageType == dhcpv6.MessageTypeRequest ||
		msg.MessageType == dhcpv6.MessageTypeRenew ||
		msg.MessageType == dhcpv6.MessageTypeDecline ||
		msg.MessageType == dhcpv6.MessageTypeRelease {
		// RFC8415 §16.{6,8,10,11}
		// These message types MUST be discarded if they *don't* contain a ServerID option
		log.Debug("missing required server ID, dropping")
		return nil, true
	}
	dhcpv6.WithServerID(*v6ServerID)(resp)
	return resp, false
}

// Handler4 handles DHCPv4 packets for the server_id plugin.
func Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.OpCode != dhcpv4.OpcodeBootRequest {
		log.Warningf("not a BootRequest, ignoring")
		return resp, false
	}
	serverid := v4ServerID
	// If this is a relay request and the Relay Agent Information option
	// contains a Server ID Override Sub-Option that we are willing to
	// use, use it.
	rai := req.RelayAgentInfo()
	if v4Overrides != nil && rai != nil {
		if ip := dhcpv4.GetIP(dhcpv4.ServerIdentifierOverrideSubOption, (*rai).Options); ip != nil {
			for _, allowed := range v4Overrides {
				if allowed.Equal(ip) {
					serverid = allowed
					break
				}
			}
		}
	}
	if serverid == nil {
		log.Infof("received request without an authorized override, dropping")
		return nil, true
	}
	if req.ServerIPAddr != nil &&
		!req.ServerIPAddr.Equal(net.IPv4zero) &&
		!req.ServerIPAddr.Equal(serverid) {
		log.Infof("request server ID %v does not match ours %v, dropping", req.ServerIPAddr, v4ServerID)
		return nil, true
	}
	resp.ServerIPAddr = make(net.IP, net.IPv4len)
	copy(resp.ServerIPAddr[:], serverid)
	resp.UpdateOption(dhcpv4.OptServerIdentifier(serverid))
	return resp, false
}

func parseIP4(arg string) (net.IP, error) {
	serverID := net.ParseIP(arg)
	if serverID == nil {
		return nil, errors.New("invalid or empty IP address")
	}
	if serverID.To4() == nil || serverID.IsUnspecified() {
		return nil, errors.New("not a valid IPv4 address")
	}
	return serverID.To4(), nil
}

func setup4(args ...string) (handler.Handler4, error) {
	log.Printf("loading `server_id` plugin for DHCPv4")
	if len(args) < 1 {
		return nil, errors.New("DHCPv4 server_id plugin needs an argument")
	}
	var err error
	if args[0] == "override_only" {
		v4ServerID = nil
		log.Infof("DHCPv4 rejecting all requests except for authorized relays")
	} else {
		if v4ServerID, err = parseIP4(args[0]); err != nil {
			log.Errorf("error parsing serverid %s: %v", args[0], err)
			return nil, err
		}
		log.Infof("DHCPv4 server_id %s", v4ServerID)
	}
	v4Overrides = nil
	for _, arg := range args[1:] {
		if serverid, err := parseIP4(arg); err == nil {
			v4Overrides = append(v4Overrides, serverid)
		} else {
			log.Errorf("error parsing override %s: %v", arg, err)
			return nil, err
		}
	}
	if v4Overrides != nil {
		log.Infof("accepting serverid overrides for authorized relays %s", v4Overrides)
	}
	if v4ServerID == nil && v4Overrides == nil {
		return nil, errors.New("override_only requires at least one authorized relay")
	}
	return Handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	log.Printf("loading `server_id` plugin for DHCPv6: %v", args)
	if len(args) < 2 {
		return nil, errors.New("need a DUID type and value")
	}
	duidType := args[0]
	if duidType == "" {
		return nil, errors.New("got empty DUID type")
	}
	duidValue := args[1]
	if duidValue == "" {
		return nil, errors.New("got empty DUID value")
	}
	duidType = strings.ToLower(duidType)
	hwaddr, err := net.ParseMAC(duidValue)
	if err != nil {
		return nil, err
	}
	switch duidType {
	case "ll", "duid-ll", "duid_ll":
		v6ServerID = &dhcpv6.Duid{
			Type: dhcpv6.DUID_LL,
			// sorry, only ethernet for now
			HwType:        iana.HWTypeEthernet,
			LinkLayerAddr: hwaddr,
		}
	case "llt", "duid-llt", "duid_llt":
		v6ServerID = &dhcpv6.Duid{
			Type: dhcpv6.DUID_LLT,
			// sorry, zero-time for now
			Time: 0,
			// sorry, only ethernet for now
			HwType:        iana.HWTypeEthernet,
			LinkLayerAddr: hwaddr,
		}
	case "en", "uuid":
		return nil, errors.New("EN/UUID DUID type not supported yet")
	default:
		return nil, errors.New("Opaque DUID type not supported yet")
	}
	log.Infof("using %s %s", duidType, duidValue)

	return Handler6, nil
}
