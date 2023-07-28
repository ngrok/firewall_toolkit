package rule

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/stretchr/testify/assert"
)

func TestBuilder(t *testing.T) {
	t.Run("success all matches", func(t *testing.T) {
		exprs, err := Build(
			expr.VerdictDrop,

			AddressFamily(expressions.IPv4),
			TransportProtocol(expressions.AnyTransport),

			SourceAddress(netip.MustParseAddr("192.168.1.100")),
			SourcePort(6100),

			DestinationAddress(netip.MustParseAddr("10.0.0.100")),
			DestinationPort(443),

			ConnectionTrackingState(expr.CtStateBitNEW|expr.CtStateBitESTABLISHED),

			Any(expressions.Counter()),
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
			expr.VerdictAccept,

			AddressFamily(expressions.IPv4),
			AddressFamily(expressions.IPv6),

			DestinationPort(8080),
		)
		assert.Error(t, err)
	})

	t.Run("multiple transports", func(t *testing.T) {
		_, err := Build(
			expr.VerdictAccept,

			TransportProtocol(expressions.UDP),
			TransportProtocol(expressions.UDP),

			DestinationPort(8080),
		)
		assert.Error(t, err)
	})

	t.Run("mixing family and ip", func(t *testing.T) {
		_, err := Build(
			expr.VerdictAccept,

			AddressFamily(expressions.IPv4),

			SourceAddress(netip.MustParseAddr("::1")),
		)
		assert.Error(t, err)

		_, err = Build(
			expr.VerdictAccept,

			AddressFamily(expressions.IPv6),

			SourceAddress(netip.MustParseAddr("127.0.0.1")),
		)
		assert.Error(t, err)
	})

	t.Run("verify netlink", func(t *testing.T) {
		table := &nftables.Table{
			Family: nftables.TableFamilyINet,
			Name:   "testtable",
		}

		chain := &nftables.Chain{
			Table: table,
			Name:  "testchain",
		}

		want := [][]byte{
			// start batch
			{0x0, 0x0, 0x0, 0xa},
			// 0xd, 0xe, 0xa, 0xd at the end is our ID
			{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xe, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x0, 0x0, 0x0, 0x84, 0x0, 0x4, 0x80, 0x24, 0x0, 0x1, 0x80, 0x9, 0x0, 0x1, 0x0, 0x6d, 0x65, 0x74, 0x61, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0, 0x2, 0x80, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0xf, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0x63, 0x6d, 0x70, 0x0, 0x20, 0x0, 0x2, 0x80, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0x3, 0x80, 0x5, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x30, 0x0, 0x1, 0x80, 0xe, 0x0, 0x1, 0x0, 0x69, 0x6d, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x0, 0x0, 0x0, 0x1c, 0x0, 0x2, 0x80, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x2, 0x80, 0xc, 0x0, 0x2, 0x80, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8, 0x0, 0x7, 0x0, 0xd, 0xe, 0xa, 0xd},
			// end batch
			{0x0, 0x0, 0x0, 0xa},
		}

		c := testDialWithWant(t, want)

		res, err := Build(expr.VerdictAccept, AddressFamily(expressions.IPv4))
		assert.Nil(t, err)
		rD := NewRuleData([]byte{0xd, 0xe, 0xa, 0xd}, res)

		// we only test the private add since we don't yet have a good way to test responses from netlink, only messages to netlink
		add(c, table, chain, rD)
		c.Flush()
	})
}
