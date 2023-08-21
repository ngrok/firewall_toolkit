//go:build linux

package set

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
)

func TestNewSetBadType(t *testing.T) {
	want := [][]byte{
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// add testtable
		// "0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65" == "testtable"
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
	}
	c := testDialWithWant(t, want)

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	})
	res, err := New(c, table, "testset", nftables.TypeARPHRD)
	assert.Error(t, err)
	assert.Equal(t, Set{}, res)
	c.Flush()
}

func TestNewV4Set(t *testing.T) {
	want := [][]byte{
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// add testtable
		// "0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65" == "testtable"
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0},
		// add set
		// "0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74" == "testset"
		// "0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72" == "counter"
		// "0x0, 0x0, 0x0, 0x7, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x4" == nftables.TypeIPAddr
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x4, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x7, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x4, 0x8, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x1, 0xa, 0x0, 0xd, 0x0, 0x0, 0x4, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0, 0x11, 0x80, 0xc, 0x0, 0x1, 0x0, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x0, 0x4, 0x0, 0xa, 0x0},
		// init elements in set
		// "0xc0, 0x0, 0x2, 0x1" == "192.0.2.1"
		{0x1, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x1, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x2c, 0x0, 0x3, 0x80, 0x10, 0x0, 0x1, 0x80, 0xc, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xc0, 0x0, 0x2, 0x1, 0x18, 0x0, 0x2, 0x80, 0x8, 0x0, 0x3, 0x80, 0x0, 0x0, 0x0, 0x1, 0xc, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xc0, 0x0, 0x2, 0x2},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// clear the set
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
	}

	c := testDialWithWant(t, want)

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	})
	res, err := New(c, table, "testset", nftables.TypeIPAddr)
	assert.Nil(t, err)

	assert.True(t, res.set.Counter)
	assert.True(t, res.set.Interval)
	assert.Equal(t, "testset", res.set.Name)
	assert.Equal(t, "testtable", res.set.Table.Name)
	assert.Equal(t, nftables.TypeIPAddr, res.set.KeyType)
	c.Flush()
}

func TestNewV6Set(t *testing.T) {
	want := [][]byte{
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// add testtable
		// "0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65" == "testtable"
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0},
		// add set
		// "0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74" == "testset"
		// "0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72" == "counter"
		// "0x0, 0x0, 0x0, 0x8, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x10" == nftables.TypeIP6Addr
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x4, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x10, 0x8, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x2, 0xa, 0x0, 0xd, 0x0, 0x0, 0x4, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0, 0x11, 0x80, 0xc, 0x0, 0x1, 0x0, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x0, 0x4, 0x0, 0xa, 0x0},
		// init elements in set
		{0x1, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x2, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x44, 0x0, 0x3, 0x80, 0x1c, 0x0, 0x1, 0x80, 0x18, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x0, 0x20, 0x1, 0xd, 0xb8, 0x85, 0xa3, 0x0, 0x1, 0x0, 0x1, 0x8a, 0x2e, 0x3, 0x70, 0x73, 0x34, 0x24, 0x0, 0x2, 0x80, 0x8, 0x0, 0x3, 0x80, 0x0, 0x0, 0x0, 0x1, 0x18, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x0, 0x20, 0x1, 0xd, 0xb8, 0x85, 0xa3, 0x0, 0x1, 0x0, 0x1, 0x8a, 0x2e, 0x3, 0x70, 0x73, 0x35},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// clear the set
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
	}

	c := testDialWithWant(t, want)

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	})
	res, err := New(c, table, "testset", nftables.TypeIP6Addr)
	assert.Nil(t, err)

	assert.True(t, res.set.Counter)
	assert.True(t, res.set.Interval)
	assert.Equal(t, "testset", res.set.Name)
	assert.Equal(t, "testtable", res.set.Table.Name)
	assert.Equal(t, nftables.TypeIP6Addr, res.set.KeyType)
	c.Flush()
}

func TestNewPortSet(t *testing.T) {
	want := [][]byte{
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// add testtable
		// "0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65" == "testtable"
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x8, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0},
		// add set
		// "0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74" == "testset"
		// "0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72" == "counter"
		// "0x0, 0x0, 0x0, 0xd, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x2" == nftables.TypeInetService
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x4, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0xd, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x2, 0x8, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x3, 0xa, 0x0, 0xd, 0x0, 0x0, 0x4, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0, 0x11, 0x80, 0xc, 0x0, 0x1, 0x0, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x0, 0x4, 0x0, 0xa, 0x0},
		// init elements in set
		{0x1, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x3, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x2c, 0x0, 0x3, 0x80, 0x10, 0x0, 0x1, 0x80, 0xc, 0x0, 0x1, 0x80, 0x6, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x18, 0x0, 0x2, 0x80, 0x8, 0x0, 0x3, 0x80, 0x0, 0x0, 0x0, 0x1, 0xc, 0x0, 0x1, 0x80, 0x6, 0x0, 0x1, 0x0, 0x0, 0x2, 0x0, 0x0},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// clear the set
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
	}

	c := testDialWithWant(t, want)

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	})
	res, err := New(c, table, "testset", nftables.TypeInetService)
	assert.Nil(t, err)

	assert.True(t, res.set.Counter)
	assert.True(t, res.set.Interval)
	assert.Equal(t, "testset", res.set.Name)
	assert.Equal(t, "testtable", res.set.Table.Name)
	assert.Equal(t, nftables.TypeInetService, res.set.KeyType)
	c.Flush()
}

func TestClearAndAddElements(t *testing.T) {
	want := [][]byte{
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// flush set
		// "0xe" == unix.NFT_MSG_DELSETELEM
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0},
		// add elements
		// "0xc0, 0x0, 0x2, 0x1" == "192.0.2.1"
		{0x1, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0, 0x8, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0x2c, 0x0, 0x3, 0x80, 0x10, 0x0, 0x1, 0x80, 0xc, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xc0, 0x0, 0x2, 0x1, 0x18, 0x0, 0x2, 0x80, 0x8, 0x0, 0x3, 0x80, 0x0, 0x0, 0x0, 0x1, 0xc, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xc0, 0x0, 0x2, 0x2},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
	}

	c := testDialWithWant(t, want)

	nfTable := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	}

	nfSet := &nftables.Set{
		Name:     "testset",
		Table:    nfTable,
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
		Counter:  true,
	}
	set := Set{set: nfSet}

	setData, err := AddressStringToSetData("192.0.2.1")
	assert.Nil(t, err)
	err = set.ClearAndAddElements(c, []SetData{setData})
	assert.Nil(t, err)
	c.Flush()
}

func TestUpdateSetBadType(t *testing.T) {
	want := [][]byte{
		// batch begin
		{0x0, 0x0, 0x0, 0xa},
		// "0xe" == unix.NFT_MSG_DELSETELEM
		{0x1, 0x0, 0x0, 0x0, 0xe, 0x0, 0x1, 0x0, 0x74, 0x65, 0x73, 0x74, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x74, 0x65, 0x73, 0x74, 0x73, 0x65, 0x74, 0x0},
		// batch end
		{0x0, 0x0, 0x0, 0xa},
	}

	c := testDialWithWant(t, want)

	nfTable := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "testtable",
	}

	nfSet := &nftables.Set{
		Name:     "testset",
		Table:    nfTable,
		KeyType:  nftables.TypeARPHRD,
		Interval: true,
		Counter:  true,
	}
	set := Set{set: nfSet}

	setData, err := AddressStringToSetData("192.0.2.1")
	assert.Nil(t, err)
	err = set.ClearAndAddElements(c, []SetData{setData})
	assert.Error(t, err)
	c.Flush()
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

func TestGenerateSetElementsEmpty(t *testing.T) {
	res, err := generateElements(nftables.TypeIPAddr, []SetData{})
	assert.Nil(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsBadType(t *testing.T) {
	setData, err := AddressStringsToSetData([]string{"198.51.100.1-198.51.100.100"})
	assert.Nil(t, err)

	res, err := generateElements(nftables.TypeARPHRD, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsMismatchedIPVersionsV4(t *testing.T) {
	setData, err := AddressStringsToSetData([]string{"198.51.100.1-198.51.100.100"})
	assert.Nil(t, err)

	res, err := generateElements(nftables.TypeIP6Addr, setData)
	assert.Nil(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsMismatchedIPVersionsV6(t *testing.T) {
	setData, err := AddressStringsToSetData([]string{"2001:db80:85a3:1:1:8a2e:1370:7336-2001:db80:85a3:1:1:8a2e:1370:7339"})
	assert.Nil(t, err)

	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Nil(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsAddressInvalidRangeV4(t *testing.T) {
	setData, err := AddressStringsToSetData([]string{"198.51.100.100-198.51.100.1"})
	assert.Nil(t, err)

	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsAddressInvalidRangeV6(t *testing.T) {
	setData, err := AddressStringsToSetData([]string{"2001:db80:85a3:1:1:8a2e:1370:7336-2001:db80:85a3:1:1:8a2e:1370:7334"})
	assert.Nil(t, err)

	res, err := generateElements(nftables.TypeIP6Addr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsInvalidIPV4(t *testing.T) {
	setData, err := AddressStringsToSetData([]string{"0.0.0.0"})
	assert.Nil(t, err)

	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsInvalidIPV6(t *testing.T) {
	setData, err := AddressStringsToSetData([]string{"::"})
	assert.Nil(t, err)

	res, err := generateElements(nftables.TypeIP6Addr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsInvalidPrefix(t *testing.T) {
	setData := []SetData{{Prefix: netip.Prefix{}}}
	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsInvalidPrefixV4(t *testing.T) {
	setData := []SetData{
		{Prefix: netip.MustParsePrefix("0.0.0.0/30")},
	}
	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsInvalidPrefixV6(t *testing.T) {
	setData := []SetData{
		{Prefix: netip.MustParsePrefix("::/30")},
	}
	res, err := generateElements(nftables.TypeIP6Addr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsEmptySetDataPorts(t *testing.T) {
	setData := []SetData{{}}
	res, err := generateElements(nftables.TypeInetService, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsEmptySetDataAddresses(t *testing.T) {
	setData := []SetData{{}}
	res, err := generateElements(nftables.TypeIP6Addr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsMultipleSetDataPorts(t *testing.T) {
	setData := []SetData{{Port: 1000, PortRangeStart: 1001}}
	res, err := generateElements(nftables.TypeInetService, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsMultipleSetDataAddresses(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.100")
	start := netip.MustParseAddr("198.51.100.101")
	setData := []SetData{{Address: addr, AddressRangeStart: start}}
	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsMultipleSetDataAddressesPrefix(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.100")
	prefix := netip.MustParsePrefix("198.51.100.101/30")
	setData := []SetData{{Address: addr, Prefix: prefix}}
	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsMultipleSetDataAddressRangePrefix(t *testing.T) {
	start := netip.MustParseAddr("198.51.100.100")
	prefix := netip.MustParsePrefix("198.51.100.101/30")
	setData := []SetData{{AddressRangeStart: start, Prefix: prefix}}
	res, err := generateElements(nftables.TypeIPAddr, setData)
	assert.Error(t, err)
	assert.Equal(t, []nftables.SetElement{}, res)
}

func TestGenerateSetElementsAddressesV4Range(t *testing.T) {
	processGoodSetElements(t, nftables.TypeIPAddr, []string{"198.51.100.1-198.51.100.100"})
}

func TestGenerateSetElementsAddressesV6Range(t *testing.T) {
	processGoodSetElements(t, nftables.TypeIP6Addr, []string{"2001:db80:85a3:1:1:8a2e:1370:7336-2001:db80:85a3:1:1:8a2e:1370:7339"})
}

func TestGenerateSetElementsAddressesV4(t *testing.T) {
	processGoodSetElements(t, nftables.TypeIPAddr, []string{"198.51.100.1"})
}

func TestGenerateSetElementsAddressesV6(t *testing.T) {
	processGoodSetElements(t, nftables.TypeIP6Addr, []string{"2001:db80:85a3:1:1:8a2e:1370:7336"})
}

func TestGenerateSetElementsAddressesV4Prefix(t *testing.T) {
	processGoodSetElements(t, nftables.TypeIPAddr, []string{"198.51.100.1/30"})
}

func TestGenerateSetElementsAddressesV6Prefix(t *testing.T) {
	processGoodSetElements(t, nftables.TypeIP6Addr, []string{"2001:db80:1234::/48"})
}

func TestGenerateSetElementsPort(t *testing.T) {
	processGoodSetElements(t, nftables.TypeInetService, []string{"8909"})
}

func TestGenerateSetElementsPortRange(t *testing.T) {
	processGoodSetElements(t, nftables.TypeInetService, []string{"8909-10000"})
}

func processGoodSetElements(t *testing.T, keyType nftables.SetDatatype, addressStrings []string) {
	setData := []SetData{}
	var err error
	switch keyType {
	case nftables.TypeIPAddr, nftables.TypeIP6Addr:
		setData, err = AddressStringsToSetData(addressStrings)
		assert.Nil(t, err)
	case nftables.TypeInetService:
		setData, err = PortStringsToSetData(addressStrings)
		assert.Nil(t, err)
	}

	elements, err := generateElements(keyType, setData)
	assert.Nil(t, err)

	assert.Equal(t, 2, len(elements))

	assert.NotNil(t, elements[0].Key)
	assert.NotNil(t, elements[1].Key)
	assert.True(t, elements[1].IntervalEnd)

	switch keyType {
	case nftables.TypeIPAddr, nftables.TypeIP6Addr:
		start, ok := netip.AddrFromSlice(elements[0].Key)
		assert.True(t, ok)
		end, ok := netip.AddrFromSlice(elements[1].Key)
		assert.True(t, ok)
		assert.True(t, start.Less(end))
	case nftables.TypeInetService:
		start := binaryutil.BigEndian.Uint16((elements[0].Key))
		end := binaryutil.BigEndian.Uint16((elements[1].Key))
		assert.True(t, start < end)
	}
}

func TestRuleDataDelta(t *testing.T) {
	tests := []struct {
		current    []SetData
		incoming   []SetData
		wantAdd    []SetData
		wantRemove []SetData
	}{
		{
			[]SetData{{Port: 8000}},
			[]SetData{{Port: 8000}, {Port: 8001}},
			[]SetData{{Port: 8001}},
			[]SetData{},
		},
		{
			[]SetData{{Port: 8000}},
			[]SetData{{Port: 8001}, {Port: 8002}},
			[]SetData{{Port: 8001}, {Port: 8002}},
			[]SetData{{Port: 8000}},
		},
		{
			[]SetData{{PortRangeStart: 8000, PortRangeEnd: 9000}},
			[]SetData{{Port: 8001}, {Port: 8002}},
			[]SetData{{Port: 8001}, {Port: 8002}},
			[]SetData{{PortRangeStart: 8000, PortRangeEnd: 9000}},
		},
		{
			[]SetData{{Address: netip.MustParseAddr("192.0.2.0")}},
			[]SetData{{Address: netip.MustParseAddr("192.0.2.0")}, {Address: netip.MustParseAddr("192.0.2.1")}},
			[]SetData{{Address: netip.MustParseAddr("192.0.2.1")}},
			[]SetData{},
		},
		{
			[]SetData{},
			[]SetData{{Address: netip.MustParseAddr("192.0.2.0")}, {Address: netip.MustParseAddr("192.0.2.1")}},
			[]SetData{{Address: netip.MustParseAddr("192.0.2.0")}, {Address: netip.MustParseAddr("192.0.2.1")}},
			[]SetData{},
		},
		{
			[]SetData{{AddressRangeStart: netip.MustParseAddr("192.0.2.0"), AddressRangeEnd: netip.MustParseAddr("192.0.2.255")}},
			[]SetData{{Address: netip.MustParseAddr("192.0.2.5")}, {Address: netip.MustParseAddr("192.0.2.6")}},
			[]SetData{{Address: netip.MustParseAddr("192.0.2.6")}, {Address: netip.MustParseAddr("192.0.2.5")}},
			[]SetData{{AddressRangeStart: netip.MustParseAddr("192.0.2.0"), AddressRangeEnd: netip.MustParseAddr("192.0.2.255")}},
		},
		{
			[]SetData{{Prefix: netip.MustParsePrefix("192.0.2.0/16")}},
			[]SetData{{Prefix: netip.MustParsePrefix("192.0.2.0/24")}, {Prefix: netip.MustParsePrefix("192.168.1.0/24")}},
			[]SetData{{Prefix: netip.MustParsePrefix("192.0.2.0/24")}, {Prefix: netip.MustParsePrefix("192.168.1.0/24")}},
			[]SetData{{Prefix: netip.MustParsePrefix("192.0.2.0/16")}},
		},
	}

	for _, test := range tests {
		add, remove := genSetDataDelta(test.current, test.incoming)

		assert.ElementsMatch(t, add, test.wantAdd)
		assert.ElementsMatch(t, remove, test.wantRemove)
	}

}

func TestUpdateElements(t *testing.T) {
	// FIXME before merging
}

func TestGetSet(t *testing.T) {
	nfSet := &nftables.Set{
		Name:     "testset",
		Table:    &nftables.Table{},
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
		Counter:  true,
	}

	set := Set{set: nfSet}

	assert.Equal(t, nfSet, set.GetSet())
}

func TestManagerGetSet(t *testing.T) {
	nfSet := &nftables.Set{
		Name:     "testset",
		Table:    &nftables.Table{},
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
		Counter:  true,
	}

	set := Set{set: nfSet}

	mS := ManagedSet{
		set: set,
	}

	mSet := mS.GetSet()

	assert.Equal(t, nfSet, mSet.GetSet())
}

func TestBadIntervalCountedAddrSetData(t *testing.T) {
	elements := []nftables.SetElement{
		{Key: []byte{198, 51, 100, 2}, IntervalEnd: false},
		{Key: []byte{198, 51, 100, 1}, IntervalEnd: true},
	}

	res, err := addrSetData(elements)

	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestGoodCountedAddrSetData(t *testing.T) {
	elements := []nftables.SetElement{
		{Key: []byte{198, 51, 100, 2}, IntervalEnd: true},
		{Key: []byte{198, 51, 100, 1}, Counter: &expr.Counter{Bytes: 100, Packets: 1}},
		{Key: []byte{203, 0, 113, 104}, IntervalEnd: true},
		{Key: []byte{203, 0, 113, 100}, Counter: &expr.Counter{Bytes: 200, Packets: 2}},
	}

	res, err := addrSetData(elements)

	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, SetData{bytes: 100, packets: 1, Address: netip.MustParseAddr("198.51.100.1")}, res[0])
	assert.Equal(t, SetData{bytes: 200, packets: 2, Prefix: netip.MustParsePrefix("203.0.113.100/30")}, res[1])
}

func TestBadIntervalCountedPortSetData(t *testing.T) {
	elements := []nftables.SetElement{
		{Key: []byte{3, 234}, IntervalEnd: false},
		{Key: []byte{3, 232}, IntervalEnd: true},
	}

	res, err := portSetData(elements)

	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestGoodCountedPortSetData(t *testing.T) {
	elements := []nftables.SetElement{
		{Key: []byte{3, 234}, IntervalEnd: true},
		{Key: []byte{3, 232}, Counter: &expr.Counter{Bytes: 100, Packets: 1}},
	}

	res, err := portSetData(elements)

	assert.Nil(t, err)
	assert.Equal(t, 1, len(res))
	assert.Equal(t, SetData{bytes: 100, packets: 1, PortRangeStart: 1000, PortRangeEnd: 1001}, res[0])
}
