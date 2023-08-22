//go:build linux

package rule

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestAddRule(t *testing.T) {
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
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xe, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x0, 0x0, 0x0, 0x54, 0x0, 0x4, 0x80, 0x24, 0x0, 0x1, 0x80, 0x9, 0x0, 0x1, 0x0, 0x6d, 0x65, 0x74, 0x61, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0, 0x2, 0x80, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0xf, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0x63, 0x6d, 0x70, 0x0, 0x20, 0x0, 0x2, 0x80, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0x3, 0x80, 0x5, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x8, 0x0, 0x7, 0x0, 0xd, 0xe, 0xa, 0xd},
		// end batch
		{0x0, 0x0, 0x0, 0xa},
	}

	c := testDialWithWant(t, want)

	res, err := expressions.CompareProtocolFamily(unix.NFPROTO_IPV4)
	assert.Nil(t, err)
	rD := NewRuleData([]byte{0xd, 0xe, 0xa, 0xd}, res)

	// we only test the private add since we don't yet have a good way to test responses from netlink, only messages to netlink
	add(c, table, chain, rD)
	assert.Nil(t, c.Flush())
}

func testDialWithWant(t *testing.T, want [][]byte) *nftables.Conn {
	// slightly modified version of https://github.com/google/nftables/blob/main/nftables_test.go#L297
	c, err := nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				assert.Nil(t, err)

				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %#v", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: got: %#v, want: %#v", idx, got, want)
				}
				want = want[1:]
			}
			return req, nil
		}))

	assert.Nil(t, err)

	return c
}

func TestFindRuleByID(t *testing.T) {
	rules := []*nftables.Rule{
		{UserData: []byte{0x1}},
		{UserData: []byte{0xa}},
		{UserData: []byte{0xb}},
	}

	rule1 := findRuleByID([]byte{0x1}, rules)
	assert.Equal(t, rule1.UserData, []byte{0x1})

	rule2 := findRuleByID([]byte{0xa}, rules)
	assert.Equal(t, rule2.UserData, []byte{0xa})

	rule3 := findRuleByID([]byte{0xb}, rules)
	assert.Equal(t, rule3.UserData, []byte{0xb})

	ruleBad := findRuleByID([]byte{0x5}, rules)
	assert.Equal(t, ruleBad, &nftables.Rule{})
}

func TestGenRuleDelta(t *testing.T) {
	tests := []struct {
		current    []*nftables.Rule
		incoming   []RuleData
		wantAdd    []RuleData
		wantRemove []*nftables.Rule
	}{
		{
			[]*nftables.Rule{{UserData: []byte{0xc, 0xa, 0xf, 0xe}}},
			[]RuleData{{ID: []byte{0xc, 0xa, 0xf, 0xe}}, {ID: []byte{0xb, 0xe, 0xe, 0xf}}},
			[]RuleData{{ID: []byte{0xb, 0xe, 0xe, 0xf}}},
			[]*nftables.Rule{},
		},
		{
			[]*nftables.Rule{},
			[]RuleData{{ID: []byte{0xc, 0xa, 0xf, 0xe}}, {ID: []byte{0xb, 0xe, 0xe, 0xf}}},
			[]RuleData{{ID: []byte{0xc, 0xa, 0xf, 0xe}}, {ID: []byte{0xb, 0xe, 0xe, 0xf}}},
			[]*nftables.Rule{},
		},
		{
			[]*nftables.Rule{{UserData: []byte{0xc, 0xa, 0xf, 0xe}}, {UserData: []byte{0xb, 0xe, 0xe, 0xf}}},
			[]RuleData{},
			[]RuleData{},
			[]*nftables.Rule{{UserData: []byte{0xc, 0xa, 0xf, 0xe}}, {UserData: []byte{0xb, 0xe, 0xe, 0xf}}},
		},
		{
			[]*nftables.Rule{{UserData: []byte{0xc, 0xa, 0xf, 0xe}}, {UserData: []byte{0xb, 0xe, 0xe, 0xf}}},
			[]RuleData{{ID: []byte{0xd, 0xe, 0xa, 0xd}}},
			[]RuleData{{ID: []byte{0xd, 0xe, 0xa, 0xd}}},
			[]*nftables.Rule{{UserData: []byte{0xc, 0xa, 0xf, 0xe}}, {UserData: []byte{0xb, 0xe, 0xe, 0xf}}},
		},
	}

	for _, test := range tests {
		add, remove := genRuleDelta(test.current, test.incoming)
		assert.ElementsMatch(t, add, test.wantAdd)
		assert.ElementsMatch(t, remove, test.wantRemove)
	}

}

func TestGetRuleTarget(t *testing.T) {
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	}

	chain := &nftables.Chain{
		Table: table,
		Name:  "testchain",
	}

	ruleTarget := NewRuleTarget(table, chain)

	rtTable, rtChain := ruleTarget.GetTableAndChain()

	assert.Equal(t, table, rtTable)
	assert.Equal(t, chain, rtChain)
}

func TestManagerGetRuleTarget(t *testing.T) {
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	}

	chain := &nftables.Chain{
		Table: table,
		Name:  "testchain",
	}

	mR := ManagedRules{
		ruleTarget: NewRuleTarget(table, chain),
	}

	rt := mR.GetRuleTarget()
	rtTable, rtChain := rt.GetTableAndChain()

	assert.Equal(t, table, rtTable)
	assert.Equal(t, chain, rtChain)
}
