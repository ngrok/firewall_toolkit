package rule

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestNewRuleData(t *testing.T) {
	res, err := expressions.CompareProtocolFamily(unix.NFPROTO_IPV4)
	assert.Nil(t, err)

	id := []byte{0xd, 0xe, 0xa, 0xd}

	rD := NewRuleData(id, res)
	assert.Equal(t, rD.ID, id)

	assert.Equal(t, rD.Expressions[0], &expr.Meta{Key: 0xf, SourceRegister: false, Register: 0x1})
	assert.Equal(t, rD.Expressions[1], &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x2}})
}

func TestCounters(t *testing.T) {
	id := []byte{0xd, 0xe, 0xa, 0xd}
	bytes := uint64(9000)
	packets := uint64(1000)
	expressions := []expr.Any{&expr.Counter{Bytes: bytes, Packets: packets}}

	rd := NewRuleData(id, expressions)
	resBytes, resPackets, resError := rd.counters()

	assert.Nil(t, resError)
	assert.EqualValues(t, *resBytes, bytes)
	assert.EqualValues(t, *resPackets, packets)
}

func TestCountersNoExpressions(t *testing.T) {
	id := []byte{0xd, 0xe, 0xa, 0xd}

	rd := NewRuleData(id, []expr.Any{})
	resBytes, resPackets, resError := rd.counters()

	assert.NotNil(t, resError)
	assert.Nil(t, resBytes)
	assert.Nil(t, resPackets)
}
