package rule

import (
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
)

func TestBuilder(t *testing.T) {
	t.Run("success all matches", func(t *testing.T) {
		exprs, err := Build(
			Drop,

			AddressFamily(IPv4),
			TransportProtocol(AnyTransport),

			SourceAddress(netip.MustParseAddr("192.168.1.100")),
			SourcePort(6100),

			DestinationAddress(netip.MustParseAddr("10.0.0.100")),
			DestinationPort(443),

			ConnectionTrackingState(StateNew|StateEstablished),

			Counter(),
		)
		assert.NoError(t, err)
		assert.Len(t, exprs, 14)
		assert.IsType(t, &expr.Meta{}, exprs[0])
		assert.IsType(t, &expr.Cmp{}, exprs[1])
		assert.IsType(t, &expr.Payload{}, exprs[2])
		assert.IsType(t, &expr.Cmp{}, exprs[3])
		assert.IsType(t, &expr.Payload{}, exprs[4])
		assert.IsType(t, &expr.Cmp{}, exprs[5])
		assert.IsType(t, &expr.Payload{}, exprs[6])
		assert.IsType(t, &expr.Cmp{}, exprs[7])
		assert.IsType(t, &expr.Payload{}, exprs[8])
		assert.IsType(t, &expr.Cmp{}, exprs[9])
		assert.IsType(t, &expr.Bitwise{}, exprs[10])
		assert.IsType(t, &expr.Cmp{}, exprs[11])
		assert.IsType(t, &expr.Counter{}, exprs[12])
		assert.IsType(t, &expr.Verdict{}, exprs[13])
	})

	t.Run("multiple address families", func(t *testing.T) {
		_, err := Build(
			Accept,

			AddressFamily(IPv4),
			AddressFamily(IPv6),

			DestinationPort(8080),
		)
		assert.Error(t, err)
	})

	t.Run("multiple transports", func(t *testing.T) {
		_, err := Build(
			Accept,

			TransportProtocol(UDP),
			TransportProtocol(UDP),

			DestinationPort(8080),
		)
		assert.Error(t, err)
	})

	t.Run("mixing family and ip", func(t *testing.T) {
		_, err := Build(
			Accept,

			AddressFamily(IPv4),

			SourceAddress(netip.MustParseAddr("::1")),
		)
		assert.Error(t, err)

		_, err = Build(
			Accept,

			AddressFamily(IPv6),

			SourceAddress(netip.MustParseAddr("127.0.0.1")),
		)
		assert.Error(t, err)
	})
}
