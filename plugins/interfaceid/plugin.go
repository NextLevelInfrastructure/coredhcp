// Copyright 2023 Next Level Infrastructure, LLC
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// This plugin assigns addresses and prefixes based on the interface-id or
// circuit-id attached to the request by a DHCP relay agent.
// This plugin ignores requests that did not arrive via a relay.
// If the DHCPv4 response already contains an address assignment,
// we pass. If the DHCPv6 response already contains an assignment
// for the first IA_NA and the first IA_PD, we pass. We never
// try to assign for IA_NA or IA_PD beyond the first.

// The plugin binds a specific MAC to an IP address and/or prefix on
// one interface, and a default IP address and/or prefix may be specified
// for allocation to any other client making a request on that interface.

// The default IP address and/or prefix will be allocated to any
// client making a request from that port even if a different client already
// has an unexpired lease. This type of lease contract is appropriate for
// ISP subscribers who are allowed to connect only one router to their
// subscriber port.

// The mapping is stored in a YAML file, with one map key for each port.
// The map value is a list of leases, where each lease is a list whose
// first element is a MAC address and subsequent elements are IPv4 or
// IPv6 addresses and/or an IPv6 prefix in CIDR form. The default
// mapping for a section is the same except the first field is "default".
//
// A map key matches a request if the most-encapsulated relay message in
// the request has interfaceid OR linkaddress equal to the key, or if
// peeraddress!interfaceid OR peeraddress!linkaddress is equal to the key.
//
// It is an error for the same MAC address to appear in more than one key.
// A lease file with errors will not be loaded.
//
//  $ cat interfaceid_leases.txt
//  interfaceid:
//    us-ca-sfba.prod.example.com:Eth12/1(Port12):
//      - [00:11:22:33:44:55, 10.0.0.1]
//      - [01:23:45:67:89:01, fedb::a]
//      - [default, 10.1.2.3, fedb::1, fedb:ffff::/60]
//    us-ca-sfba.prod.example.com:Eth13/1(Port13):
//      - [...]
//
// The plugin is configured once in the server6 section and once in the
// server4 section of coredhcp's config file. Pass the lease duration as
// the first argument to the plugin and the leases file name as the second
// argument. You may use the same leases file for IPv4 and IPv6 (IPv4
// addresses are ignored for DHCPv6 and vice versa), or you may use
// different leases files of course.
//
//  $ cat config.yml
//
//  server6:
//     ...
//     plugins:
//       - interfaceid: 86400 "interfaceid_leases.txt" autorefresh
//     ...
//
// If the file path is not absolute, it is relative to the cwd where coredhcp
// is run.
//
// If the optional "autorefresh" argument is given, the plugin will try to
// refresh the lease mappings at runtime whenever the lease file is updated.

package interfaceid

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"gopkg.in/yaml.v3"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/fsnotify/fsnotify"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

const (
	autoRefreshArg = "autorefresh"
	reissueWarningDuration = time.Duration(1800) * time.Second
)

var log = logger.GetLogger("plugins/interfaceid")

var Plugin = plugins.Plugin{
	Name:   "interfaceid",
	Setup6: setup6,
	Setup4: setup4,
}

type LeaseMap map[string][]Lease

type PluginState struct {
	sync.Mutex
	Filename string
	watcher  *fsnotify.Watcher  // close this to make reload goroutine exit
        Duration time.Duration
        LeaseByMac       LeaseMap
	LeaseByInterface LeaseMap
}

func LoadLeases(filename string) (LeaseMap, error) {
	yamlfile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var enclosure struct {
		Interfaceid LeaseMap
	}
	if err = yaml.Unmarshal(yamlfile, &enclosure); err != nil {
		return nil, err
	}
	return enclosure.Interfaceid, nil
}

// We pre-process the lease map to speed up certain operations and find errors.
// If an error is returned, state has not been changed (but newleases may have been).

func (state *PluginState) UpdateFrom(newleases LeaseMap) error {
	macleases := make(LeaseMap)
	for interfaceid, leases := range newleases {
		for idx, lease := range leases {
			if len(lease.mac) == 0 {
				if idx > 0 {
					if len(leases[0].mac) == 0 {
						return fmt.Errorf("two default leases in %s", interfaceid)
					}
					sw := leases[0]
					leases[0] = lease
					leases[idx] = sw
					macleases[sw.mac] = leases[idx:idx+1]
				}
			} else {
				if _, ok := macleases[lease.mac]; ok {
					return fmt.Errorf("two leases for MAC %s in %s and %s", lease.mac, interfaceid, lease.interfaceid)
				}
				leases[idx].interfaceid = interfaceid
				macleases[lease.mac] = leases[idx:idx+1]
			}
		}
	}

	state.Lock()
	defer state.Unlock()
	state.LeaseByMac = macleases
	state.LeaseByInterface = newleases
	return nil
}

type LeaseEvent struct {
	clientid, vendorid string
	issued             time.Time
}

type Lease struct {
	mac     string     // empty if default lease on this port
	host4, host6 netip.Addr
	prefix  netip.Prefix // zero-bit mask if no prefix is available
	expires time.Time  // IsZero() if no lease issued since we started
	ultimate, penultimate LeaseEvent
	interfaceid string
}

func (lease *Lease) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tokens []string
	if err := unmarshal(&tokens); err != nil {
		return err
	}
	if len(tokens) < 2 {
		return fmt.Errorf("cannot unmarshal empty lease: %s", tokens)
	}
	if tokens[0] != "default" {
		hwaddr, err := net.ParseMAC(tokens[0])
		if err != nil {
			return fmt.Errorf("malformed hardware address: %s", tokens[0])
		}
		lease.mac = hwaddr.String()
	}
	for _, token := range tokens[1:] {
		if prefix, err := netip.ParsePrefix(token); err == nil {
			if lease.prefix.Bits() > 0 {
				return fmt.Errorf("two prefixes for lease %s", tokens)
			}
			if lease.prefix != lease.prefix.Masked() {
				return fmt.Errorf("prefix %s not in canonical form %s", lease.prefix, lease.prefix.Masked())
			}
			lease.prefix = prefix
		} else if ip, err := netip.ParseAddr(token); err == nil {
			if ip.Is4() {
				if lease.host4.IsValid() {
					return fmt.Errorf("two IPv4 hosts for lease %s", tokens)
				}
				lease.host4 = ip
			} else {
				if lease.host6.IsValid() {
					return fmt.Errorf("two IPv6 hosts for lease %s", tokens)
				}
				lease.host6 = ip
			}
		} else {
			return fmt.Errorf("cannot parse IP or prefix %s: %s", token, tokens)
		}
	}
	return nil
}

func (lease Lease) String() string {
	expires := "(not leased)"
	if !lease.expires.IsZero() {
		expires = lease.expires.String()
	}
	return fmt.Sprintf("Lease(host4=%s, host6=%s, prefix=%s, expires %s)", lease.host4.String(), lease.host6.String(), lease.prefix.String(), expires)
}

// We ignore any request that is not a relay message, because only
// relays can tell us an interface ID or link address, and those
// are the whole point of this plugin.
//
// We do not try to fulfill any IA_TA requests because we only allocate
// persistent addresses.

func (state *PluginState) Handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	respmsg, ok := resp.(*dhcpv6.Message)
	if !ok {
		log.Errorf("response message format bug: %v", respmsg)
		return nil, true
	}
	if respmsg.Options.OneIANA() != nil || respmsg.Options.OneIAPD() != nil {
		log.Infof("response already contains IA from previous plugin, passing")
		return resp, false
	}
	if !req.IsRelay() {
		log.Debug("not a relay message so no interface ID or link, passing")
		return resp, false
	}
	// inner will be the innermost relay message
	innermsg, err := dhcpv6.DecapsulateRelayIndex(req, -1)
	if err != nil {
		log.Errorf("could not decapsulate: %v", err)
		return nil, true
	}
	inner, ok := innermsg.(*dhcpv6.RelayMessage)
	if !ok {
		log.Errorf("relay message format bug: %v", innermsg)
		return nil, true
	}
	msg, err := inner.GetInnerMessage()
	if err != nil {
		log.Errorf("could not decapsulate inner message: %v", err)
		return nil, true
	}
	mac, err := dhcpv6.ExtractMAC(req)
	if err != nil {
		log.Warningf("request contains no client MAC, passing")
		return resp, false
	}
	peerstr := inner.PeerAddr.String()
	linkstr := inner.LinkAddr.String()
	if len(inner.LinkAddr) == 0 || inner.LinkAddr.IsUnspecified() {
		linkstr = "unspecified_link"
	}
	var intfstr string
	if intf := inner.Options.InterfaceID(); intf != nil {
		intfstr = string(intf)
	}
	if msg.Options.OneIANA() == nil && msg.Options.OneIAPD() == nil {
		log.Debug("no non-temporary address requested, passing")
		return resp, false
	}

	state.Lock()
	defer state.Unlock()

	leases := state.lookup(mac.String(), peerstr, linkstr, intfstr)
	if leases != nil && len(leases) > 0 {
		if !allocate6(&leases[0], state.Duration, msg, &resp) {
			log.Warningf("MAC %s peer %s link %s has no DHCPv6 address in lease", mac.String(), peerstr, linkstr)
		}
	} else {
		log.Warningf("MAC %s peer %s link %s has no DHCPv6 lease", mac.String(), peerstr, linkstr)
	}
	return resp, false
}

func (state *PluginState) lookup(macstr, peerstr, linkstr, intfstr string) []Lease {
	log.Debugf("checking lease for peer %s, interface %s, link %s, MAC %s", peerstr, intfstr, linkstr, macstr)
	if macleases, ok := state.LeaseByMac[macstr]; ok {
		if macleases[0].interfaceid == intfstr {
			log.Infof("allocating pinned MAC %s on expected interface", macstr)
			return macleases
		} else {
			log.Warningf("pinned MAC %s on interface %s but expected %s, using interface/link default", macstr, intfstr, macleases[0].interfaceid)
		}
	}
	if leases, ok := state.LeaseByInterface[peerstr + "!" + intfstr]; ok {
		log.Infof("allocating MAC %s on peer %s intf %s", macstr, peerstr, intfstr)
		return leases
	}
	if leases, ok := state.LeaseByInterface[intfstr]; ok {
		log.Infof("allocating MAC %s on intf %s (peer %s default)", macstr, intfstr, peerstr)
		return leases
	}
	if leases, ok := state.LeaseByInterface[peerstr + "!" + linkstr]; ok {
		log.Infof("allocating MAC %s on peer %s link %s", macstr, peerstr, linkstr)
		return leases
	}
	if leases, ok := state.LeaseByInterface[linkstr]; ok {
		log.Infof("allocating MAC %s on link %s (peer %s default)", macstr, linkstr, peerstr)
		return leases
	}
	return nil
}

// If the client has asked for a permanent address (IA_NA) and our lease has an
// IPv6 address, we allocate that address to the first IA_NA. If the client has
// asked for a prefix (IA_PD) and our lease has a prefix, we allocate that
// prefix to the first IA_PD. We don't try to do anything smart to allocate
// our address or prefix to the "best" IA.

func allocate6(lease *Lease, duration time.Duration, msg *dhcpv6.Message, resp *dhcpv6.DHCPv6) bool {
	var ianaResp *dhcpv6.OptIANA
	var iapdResp *dhcpv6.OptIAPD

	if iana := msg.Options.OneIANA(); iana != nil && lease.host6.IsValid() {
		ianaResp = &dhcpv6.OptIANA{
			IaId: iana.IaId,
		}
		ianaResp.Options.Add(&dhcpv6.OptIAAddress{
			IPv6Addr:          net.IP(lease.host6.AsSlice()),
			PreferredLifetime: duration,
			ValidLifetime:     duration,
		})
		(*resp).AddOption(ianaResp)
	}
	if iapd := msg.Options.OneIAPD(); iapd != nil && lease.prefix.Bits() > 0 {
		iapdResp = &dhcpv6.OptIAPD{
			IaId: iapd.IaId,
		}
		prefix := net.IPNet{
			IP:   net.IP(lease.prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(lease.prefix.Bits(), 128),
		}
		iapdResp.Options.Add(&dhcpv6.OptIAPrefix{
			Prefix:            &prefix,
			PreferredLifetime: duration,
			ValidLifetime:     duration,
		})
		(*resp).AddOption(iapdResp)
	}
	if ianaResp != nil || iapdResp != nil {
		// then we allocated something
		var cid, vid string
		if clientid := msg.GetOneOption(dhcpv6.OptionClientID); clientid != nil {
			cid = clientid.String()
		}
		if vclass := msg.GetOneOption(dhcpv6.OptionVendorClass); vclass != nil {
			vid = vclass.String()
		}
		updateLeaseTime(lease, duration, cid, vid)
		return true
	}
	return false
}

func updateLeaseTime(lease *Lease, duration time.Duration, cid, vid string) {
	now := time.Now()
	event := LeaseEvent{
		clientid: cid,
		vendorid: vid,
		issued: now,
	}
	if event.clientid != lease.ultimate.clientid && event.clientid != lease.penultimate.clientid {
		if now.Sub(lease.penultimate.issued) < reissueWarningDuration {
			log.Warningf("lease issued to 3 clients within %s: %s/%s %s/%s %s/%s %s %s", reissueWarningDuration, event.clientid, event.vendorid, lease.ultimate.clientid, lease.ultimate.vendorid, lease.penultimate.clientid, lease.penultimate.vendorid, lease, lease.interfaceid)
		}
		lease.penultimate = lease.ultimate
	} else if event.clientid != lease.ultimate.clientid {
		lease.penultimate = lease.ultimate
	}
	lease.ultimate = event
	lease.expires = now.Add(duration)
}

func (state *PluginState) Handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	if req.OpCode != dhcpv4.OpcodeBootRequest {
		log.Warningf("not a BootRequest, ignoring %d", req.OpCode)
		return resp, false
	}
	if len(req.YourIPAddr) > 0 && !req.YourIPAddr.IsUnspecified() {
		// already allocated
		return resp, false
	}
	rai := req.RelayAgentInfo()
	if rai == nil || len(req.GatewayIPAddr) == 0 || req.GatewayIPAddr.IsUnspecified() {
		log.Debug("not a relay message so no interface ID or link, passing")
		return resp, false
	}
	peerstr := req.GatewayIPAddr.String()
	var linkstr string
	if ip := dhcpv4.GetIP(dhcpv4.LinkSelectionSubOption, (*rai).Options); ip != nil {
		linkstr = ip.String()
	}
	intfstr := dhcpv4.GetString(dhcpv4.AgentCircuitIDSubOption, (*rai).Options)
	mac := req.ClientHWAddr

	state.Lock()
	defer state.Unlock()

	leases := state.lookup(mac.String(), peerstr, linkstr, intfstr)
	if leases != nil && len(leases) > 0 {
		if !allocate4(&leases[0], state.Duration, req, resp) {
			log.Warningf("MAC %s peer %s link %s has no DHCPv4 address in lease", mac.String(), peerstr, linkstr)
		}
	} else {
		log.Warningf("MAC %s peer %s link %s has no DHCPv4 lease", mac.String(), peerstr, linkstr)
	}
	return resp, false
}

func allocate4(lease *Lease, duration time.Duration, msg, resp *dhcpv4.DHCPv4) bool {
	if lease.host4.IsValid() {
		resp.YourIPAddr = net.IP(lease.host4.AsSlice())
		resp.Options.Update(dhcpv4.OptIPAddressLeaseTime(duration))
		vid := msg.ClassIdentifier()
		updateLeaseTime(lease, duration, msg.ClientHWAddr.String(), vid)
		return true
	}
	return false
}

func setup6(args ...string) (handler.Handler6, error) {
	var state PluginState
	if err := state.FromArgs(args...); err != nil {
		return nil, err
	}
	return state.Handler6, nil
}

func setup4(args ...string) (handler.Handler4, error) {
	var state PluginState
	if err := state.FromArgs(args...); err != nil {
		return nil, err
	}
	return state.Handler4, nil
}

func (state *PluginState) FromArgs(args ...string) error {
	if len(args) < 2 {
		return fmt.Errorf("need duration and filename arguments")
	}
	if duration, err := strconv.Atoi(args[0]); err == nil {
		if duration < 1 {
			return fmt.Errorf("duration %s must be positive", args[0])
		}
		state.Duration = time.Duration(duration) * time.Second
	} else {
		return fmt.Errorf("duration %s must be an integer", args[0])
	}
	state.Filename = args[1]
	if state.Filename == "" {
		return fmt.Errorf("got empty filename")
	}

	// if the autorefresh argument is not present, just load the leases
	if len(args) < 3 || args[2] != autoRefreshArg {
		leases, err := LoadLeases(state.Filename)
		if err != nil {
			return err
		}
		return state.UpdateFrom(leases)
	}
	// otherwise watch the lease file and reload on any event
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	if err = watcher.Add(state.Filename); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch %s: %w", state.Filename, err)
	}
	// avoid race by doing initial load only after we start watching
	leases, err := LoadLeases(state.Filename)
	if err != nil {
		watcher.Close()
		return err
	}
	if err := state.UpdateFrom(leases); err != nil {
		watcher.Close()
		return err
	}
	state.watcher = watcher
	go func() {
		for range watcher.Events {
			newones, err := LoadLeases(state.Filename)
			if err != nil {
				log.Warningf("failed to refresh from %s: %s", state.Filename, err)
				continue
			}
			log.Infof("refreshed %s with %d interfaces", state.Filename, len(newones))
			if err := state.UpdateFrom(newones); err != nil {
				log.Warningf("failed to update during refresh of %s: %s", state.Filename, err)
				continue
			}
		}
		log.Warningf("file refresh watcher was closed: %s", state.Filename)
	}()
	return nil
}
