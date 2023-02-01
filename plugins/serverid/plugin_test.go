// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package serverid

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/assert"
)

func makeTestDUID(uuid string) *dhcpv6.Duid {
	return &dhcpv6.Duid{
		Type: dhcpv6.DUID_UUID,
		Uuid: []byte(uuid),
	}
}

func testv4setup(t *testing.T) (req, resp *dhcpv4.DHCPv4) {
	_, err := setup4("2.4.6.8", "10.20.30.40", "100.200.3.4")
	assert.NoError(t, err)

	// prepare DHCPv4 request
	mac := "00:11:22:33:44:55"
	claddr, _ := net.ParseMAC(mac)
	discovery_req, err := dhcpv4.NewDiscovery(claddr)
	assert.NoError(t, err)
	discovery_resp, err := dhcpv4.NewReplyFromRequest(discovery_req)
	assert.NoError(t, err)
	discovery_resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	return discovery_req, discovery_resp
}

func TestAcceptServerIDV4(t *testing.T) {
	discovery_req, discovery_resp := testv4setup(t)
	// no serverid -- should be allowed
	result, stop := Handler4(discovery_req, discovery_resp)
	assert.Same(t, result, discovery_resp)
	assert.False(t, stop)

	discovery_req.ServerIPAddr = net.ParseIP("2.4.6.8").To4()
	assert.True(t, result.ServerIPAddr.Equal(discovery_req.ServerIPAddr))

	result, stop = Handler4(discovery_req, discovery_resp)
	assert.Same(t, result, discovery_resp)
	assert.False(t, stop)
	assert.True(t, result.ServerIPAddr.Equal(discovery_req.ServerIPAddr))
}

func TestAcceptInitialOverrideV4(t *testing.T) {
	discovery_req, discovery_resp := testv4setup(t)
	// no serverid -- should be allowed
	relayip := net.ParseIP("100.200.3.4").To4()
	rai := dhcpv4.OptRelayAgentInfo(
		dhcpv4.Option{Code: dhcpv4.ServerIdentifierOverrideSubOption, Value: dhcpv4.IP(relayip)},
	)
	discovery_req.UpdateOption(rai)
	result, stop := Handler4(discovery_req, discovery_resp)
	assert.Same(t, result, discovery_resp)
	assert.False(t, stop)
	assert.True(t, result.ServerIPAddr.Equal(relayip))
}

func TestRejectUnexpectedServerIDV4(t *testing.T) {
	discovery_req, discovery_resp := testv4setup(t)

	// relay serverid with no override -- should be rejected
	discovery_req.ServerIPAddr = net.ParseIP("10.20.30.40").To4()
	result, stop := Handler4(discovery_req, discovery_resp)
	assert.Nil(t, result)
	assert.True(t, stop)

	// now add server option override -- should be allowed
	rai := dhcpv4.OptRelayAgentInfo(
		dhcpv4.Option{Code: dhcpv4.ServerIdentifierOverrideSubOption, Value: dhcpv4.IP(discovery_req.ServerIPAddr)},
	)
	discovery_req.UpdateOption(rai)
	result, stop = Handler4(discovery_req, discovery_resp)
	assert.Same(t, result, discovery_resp)
	assert.False(t, stop)
	assert.True(t, result.ServerIPAddr.Equal(discovery_req.ServerIPAddr))
}

func TestRejectUnexpectedServerIDOverride(t *testing.T) {
	discovery_req, discovery_resp := testv4setup(t)

	// add server option override that we reject -- should fail
	discovery_req.ServerIPAddr = net.ParseIP("10.20.30.41").To4()
	rai := dhcpv4.OptRelayAgentInfo(
		dhcpv4.Option{Code: dhcpv4.ServerIdentifierOverrideSubOption, Value: dhcpv4.IP(net.ParseIP("10.20.30.41").To4())},
	)
	discovery_req.UpdateOption(rai)
	result, stop := Handler4(discovery_req, discovery_resp)
	assert.Nil(t, result)
	assert.True(t, stop)
}

func TestRejectBadServerIDV6(t *testing.T) {
	req, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	v6ServerID = makeTestDUID("0000000000000000")

	req.MessageType = dhcpv6.MessageTypeRenew
	dhcpv6.WithClientID(*makeTestDUID("1000000000000000"))(req)
	dhcpv6.WithServerID(*makeTestDUID("0000000000000001"))(req)

	stub, err := dhcpv6.NewReplyFromMessage(req)
	if err != nil {
		t.Fatal(err)
	}

	resp, stop := Handler6(req, stub)
	if resp != nil {
		t.Error("server_id is sending a response message to a request with mismatched ServerID")
	}
	if !stop {
		t.Error("server_id did not interrupt processing on a request with mismatched ServerID")
	}
}

func TestRejectUnexpectedServerIDV6(t *testing.T) {
	req, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	v6ServerID = makeTestDUID("0000000000000000")

	req.MessageType = dhcpv6.MessageTypeSolicit
	dhcpv6.WithClientID(*makeTestDUID("1000000000000000"))(req)
	dhcpv6.WithServerID(*makeTestDUID("0000000000000000"))(req)

	stub, err := dhcpv6.NewAdvertiseFromSolicit(req)
	if err != nil {
		t.Fatal(err)
	}

	resp, stop := Handler6(req, stub)
	if resp != nil {
		t.Error("server_id is sending a response message to a solicit with a ServerID")
	}
	if !stop {
		t.Error("server_id did not interrupt processing on a solicit with a ServerID")
	}
}

func TestAddServerIDV6(t *testing.T) {
	req, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	v6ServerID = makeTestDUID("0000000000000000")

	req.MessageType = dhcpv6.MessageTypeRebind
	dhcpv6.WithClientID(*makeTestDUID("1000000000000000"))(req)

	stub, err := dhcpv6.NewReplyFromMessage(req)
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := Handler6(req, stub)
	if resp == nil {
		t.Fatal("plugin did not return an answer")
	}

	if opt := resp.(*dhcpv6.Message).Options.ServerID(); opt == nil {
		t.Fatal("plugin did not add a ServerID option")
	} else if !opt.Equal(*v6ServerID) {
		t.Fatalf("Got unexpected DUID: expected %v, got %v", v6ServerID, opt)
	}
}

func TestRejectInnerMessageServerID(t *testing.T) {
	req, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	v6ServerID = makeTestDUID("0000000000000000")

	req.MessageType = dhcpv6.MessageTypeSolicit
	dhcpv6.WithClientID(*makeTestDUID("1000000000000000"))(req)
	dhcpv6.WithServerID(*makeTestDUID("0000000000000000"))(req)

	stub, err := dhcpv6.NewAdvertiseFromSolicit(req)
	if err != nil {
		t.Fatal(err)
	}

	relayedRequest, err := dhcpv6.EncapsulateRelay(req, dhcpv6.MessageTypeRelayForward, net.IPv6loopback, net.IPv6loopback)
	if err != nil {
		t.Fatal(err)
	}

	resp, stop := Handler6(relayedRequest, stub)
	if resp != nil {
		t.Error("server_id is sending a response message to a relayed solicit with a ServerID")
	}
	if !stop {
		t.Error("server_id did not interrupt processing on a relayed solicit with a ServerID")
	}
}
