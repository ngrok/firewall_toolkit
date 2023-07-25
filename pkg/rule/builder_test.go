package rule_test

import (
	"net/netip"
	"testing"

	"github.com/ngrok/firewall_toolkit/pkg/rule"
)

func TestBuilder(t *testing.T) {
	id := []byte{0xd, 0xe, 0xa, 0xd}

	_, err := rule.Build(
		id,

		rule.IPv4(),

		rule.SourceAddress(netip.MustParseAddr("192.168.1.100")),
		rule.SourcePort(6100),

		rule.DestinationAddress(netip.MustParseAddr("10.0.0.100")),
		rule.DestinationPort(443),

		rule.Counter(),
		rule.Statement(rule.VerdictDrop),
	)
	if err != nil {
		t.Error(err)
	}
}
