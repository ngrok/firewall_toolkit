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
