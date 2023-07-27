package rule_test

import (
	"net/netip"
	"testing"

	"github.com/ngrok/firewall_toolkit/pkg/rule"
)

func TestBuilder(t *testing.T) {
	_, err := rule.Build(
		rule.Drop,

		rule.AddressFamily(rule.IPv4),
		rule.TransportProtocol(rule.AnyTransport),

		rule.SourceAddress(netip.MustParseAddr("192.168.1.100")),
		rule.SourcePort(6100),

		rule.DestinationAddress(netip.MustParseAddr("10.0.0.100")),
		rule.DestinationPort(443),

		rule.Counter(),
	)
	if err != nil {
		t.Error(err)
	}
}
