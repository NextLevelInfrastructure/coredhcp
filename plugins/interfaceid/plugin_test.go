// Copyright 2023 Next Level Infrastructure.
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package interfaceid

import (
	"io/ioutil"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeConfig(t *testing.T) (*os.File, func()) {
	tmp, err := ioutil.TempFile("", "test_plugin_interfaceid")
	require.NoError(t, err)

	// fill temp file with valid lease lines and some comments
	_, err = tmp.WriteString(`
interfaceid:
  us-ca-sfba.prod.example.com:Eth12/1(Port12):
    - [00:11:22:33:44:55, 192.0.2.100]
    - [default, 192.0.2.101, fedb::2, fedb:ffff::/60]
    - [11:22:33:44:55:66, fedb::1]
# this is a comment
`)
	require.NoError(t, err)

	return tmp, func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
}

func newStateFromFile(t *testing.T, filename string) *PluginState {
	leases, err := LoadLeases(filename)
	if !assert.NoError(t, err) {
		return nil
	}
	var state PluginState
	state.Filename = filename
	state.Duration = time.Duration(3600) * time.Second
	state.UpdateFrom(leases)
	return &state
}

func TestLoadRecords(t *testing.T) {
	t.Run("valid leases", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()

		leases, err := LoadLeases(tmp.Name())
		if !assert.NoError(t, err) {
			return
		}

		key := "us-ca-sfba.prod.example.com:Eth12/1(Port12)"
		if assert.Equal(t, 1, len(leases)) {
			assert.Contains(t, leases, key)
		}

		state := newStateFromFile(t, tmp.Name())
		if assert.Equal(t, 2, len(state.LeaseByMac)) {
			assert.Equal(t, netip.MustParseAddr("fedb::1"), state.LeaseByMac["11:22:33:44:55:66"][0].host6)
		}
		if assert.Equal(t, 1, len(state.LeaseByInterface)) {
			leases := state.LeaseByInterface[key]
			assert.Equal(t, 3, len(leases))
		}
	})

	t.Run("too many IPs", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()

		_, err := tmp.WriteString("    - [01:02:03:44:55:66, 192.0.2.101, 192.1.1.1, fedb::2, fedb:ffff::/60]\n")
		require.NoError(t, err)
		_, err = LoadLeases(tmp.Name())
		assert.Error(t, err)
	})

	t.Run("invalid MAC", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()

		_, err := tmp.WriteString("    - [badmac, 192.0.2.101, fedb::2, fedb:ffff::/60]\n")
		require.NoError(t, err)
		_, err = LoadLeases(tmp.Name())
		assert.Error(t, err)
	})

	t.Run("invalid IP address", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()

		_, err := tmp.WriteString("    - [01:02:03:44:55:66, 192.0.2.301, fedb::2, fedb:ffff::/60]\n")
		require.NoError(t, err)
		_, err = LoadLeases(tmp.Name())
		assert.Error(t, err)
	})
}

func TestHandler4(t *testing.T) {
	t.Run("unknown MAC, then known MAC", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()
		state := newStateFromFile(t, tmp.Name())

		// prepare DHCPv4 request
		mac := "00:11:22:33:44:55"
		claddr, _ := net.ParseMAC(mac)
		req := &dhcpv4.DHCPv4{
			ClientHWAddr: claddr,
		}
		resp := &dhcpv4.DHCPv4{}
		assert.Nil(t, resp.ClientIPAddr)

		// nothing should change since there is no interface in the request
		result, stop := state.Handler4(req, resp)
		assert.Same(t, result, resp)
		assert.False(t, stop)
		assert.Nil(t, result.YourIPAddr)

		desired_clientip := net.ParseIP("192.0.2.100")
		req.GatewayIPAddr = net.ParseIP("10.0.0.10")
		rai := dhcpv4.OptRelayAgentInfo(
			dhcpv4.OptGeneric(dhcpv4.AgentCircuitIDSubOption, []byte("us-ca-sfba.prod.example.com:Eth12/1(Port12)")),
		)
		req.UpdateOption(rai)
		// now we should assign an address
		result, stop = state.Handler4(req, resp)
		assert.Same(t, result, resp)
		if !desired_clientip.Equal(result.YourIPAddr) {
			assert.Equal(t, desired_clientip, result.YourIPAddr)
		}
		assert.False(t, stop)		
	})
}

func TestHandler6(t *testing.T) {
	t.Run("unknown MAC, then known MAC", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()
		state := newStateFromFile(t, tmp.Name())

		// prepare DHCPv6 request
		mac := "11:22:33:44:55:66"
		claddr, _ := net.ParseMAC(mac)
		pref := dhcpv6.OptIAPrefix{
			PreferredLifetime: 0xaabbccdd * time.Second,
			ValidLifetime:     0xeeff0011 * time.Second,
			Prefix: &net.IPNet{
				Mask: net.CIDRMask(36, 128),
				IP:   net.IPv6loopback,
			},
		}
		req, err := dhcpv6.NewSolicit(claddr, dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, &pref))
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)
		assert.Equal(t, 0, len(resp.GetOption(dhcpv6.OptionIANA)))

		// if we handle this DHCP request, nothing should change since the lease is
		// unknown
		result, stop := state.Handler6(req, resp)
		assert.False(t, stop)
		assert.Equal(t, 0, len(result.GetOption(dhcpv6.OptionIANA)))

		relay, err := dhcpv6.EncapsulateRelay(req, dhcpv6.MessageTypeRelayForward, net.ParseIP("10.1.2.3"), net.ParseIP("10.1.1.1"))
		require.NoError(t, err)
		opt := dhcpv6.OptInterfaceID([]byte("us-ca-sfba.prod.example.com:Eth12/1(Port12)"))
		relay.UpdateOption(opt)
		result, stop = state.Handler6(relay, resp)
		assert.False(t, stop)
		res := result.GetOption(dhcpv6.OptionIANA)
		if assert.Equal(t, 1, len(res)) {
			opt := result.GetOneOption(dhcpv6.OptionIANA)
			assert.Contains(t, opt.String(), "IP=fedb::1")
		}
		assert.Equal(t, 0, len(result.GetOption(dhcpv6.OptionIAPD)))
	})

	t.Run("prefix allocation", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()
		state := newStateFromFile(t, tmp.Name())

		// prepare DHCPv6 request
		mac := "11:22:33:44:ff:ff"
		claddr, _ := net.ParseMAC(mac)
		pref := dhcpv6.OptIAPrefix{
			PreferredLifetime: 0xaabbccdd * time.Second,
			ValidLifetime:     0xeeff0011 * time.Second,
			Prefix: &net.IPNet{
				Mask: net.CIDRMask(36, 128),
				IP:   net.IPv6loopback,
			},
		}
		req, err := dhcpv6.NewSolicit(claddr, dhcpv6.WithIAPD([4]byte{1, 2, 3, 4}, &pref))
		require.NoError(t, err)
		resp, err := dhcpv6.NewAdvertiseFromSolicit(req)
		require.NoError(t, err)
		assert.Equal(t, 0, len(resp.GetOption(dhcpv6.OptionIANA)))

		relay, err := dhcpv6.EncapsulateRelay(req, dhcpv6.MessageTypeRelayForward, net.ParseIP("f0db:f0db:f0db::1"), net.ParseIP("f2db:f2db::2"))
		require.NoError(t, err)
		opt := dhcpv6.OptInterfaceID([]byte("us-ca-sfba.prod.example.com:Eth12/1(Port12)"))
		relay.UpdateOption(opt)
		result, stop := state.Handler6(relay, resp)
		assert.False(t, stop)
		res := result.GetOption(dhcpv6.OptionIANA)
		if assert.Equal(t, 1, len(res)) {
			opt := result.GetOneOption(dhcpv6.OptionIANA)
			assert.Contains(t, opt.String(), "IP=fedb::2")
		}
		iapd := result.GetOption(dhcpv6.OptionIAPD)
		if assert.Equal(t, 1, len(iapd)) {
			opt := result.GetOneOption(dhcpv6.OptionIAPD)
			assert.Contains(t, opt.String(), "Prefix=fedb:ffff::/60")
		}
	})

	t.Run("autorefresh enabled", func(t *testing.T) {
		tmp, cleanup := makeConfig(t)
		defer cleanup()
		newStateFromFile(t, tmp.Name())
		var state PluginState
		err := state.FromArgs("84600", tmp.Name(), autoRefreshArg)
		require.NoError(t, err)

		assert.Equal(t, 1, len(state.LeaseByInterface))

		// we add more leases to the file
		// this should trigger an event to refresh the leases database
		// without calling setupFile again
		_, err = tmp.WriteString("  Port666:\n")
		require.NoError(t, err)
		_, err = tmp.WriteString("    - [00:11:22:33:e4:f5, 192.0.2.100]\n")
		require.NoError(t, err)
		// since the event is processed asynchronously, give it a little time
		time.Sleep(time.Millisecond * 100)
		// an additional record should show up in the database
		// but we should respect the locking first
		state.Lock()
		defer state.Unlock()

		assert.Equal(t, 2, len(state.LeaseByInterface))
		state.watcher.Close()
	})
}
