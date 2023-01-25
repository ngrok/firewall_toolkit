package set

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBadAddressStringsListAddress(t *testing.T) {
	bad := []string{"0"}

	res, err := AddressStringsToSetData(bad)
	assert.Error(t, err)
	assert.Equal(t, []SetData{}, res)
}

func TestBadAddressStringsListRange(t *testing.T) {
	bad := []string{"0-0"}

	res, err := AddressStringsToSetData(bad)
	assert.Error(t, err)
	assert.Equal(t, []SetData{}, res)
}

func TestBadAddressStringsListPrefix(t *testing.T) {
	bad := []string{"0/0"}

	res, err := AddressStringsToSetData(bad)
	assert.Error(t, err)
	assert.Equal(t, []SetData{}, res)
}

func TestBadPrefixString(t *testing.T) {
	res, err := PrefixStringToSetData("198.51.100.200/40")
	assert.Error(t, err)
	assert.Equal(t, SetData{}, res)
}

func TestBadAddressRangeStringStart(t *testing.T) {
	res, err := AddressRangeStringToSetData("bad", "198.51.100.200")
	assert.Error(t, err)
	assert.Equal(t, SetData{}, res)
}

func TestBadAddressRangeStringEnd(t *testing.T) {
	res, err := AddressRangeStringToSetData("198.51.100.200", "bad")
	assert.Error(t, err)
	assert.Equal(t, SetData{}, res)
}

func TestBadPortStringToSetData(t *testing.T) {
	res, err := PortStringToSetData("bad")
	assert.Error(t, err)
	assert.Equal(t, SetData{}, res)
}

func TestBadPortRangeStringToSetDataStart(t *testing.T) {
	res, err := PortRangeStringToSetData("bad", "1234")
	assert.Error(t, err)
	assert.Equal(t, SetData{}, res)
}

func TestBadPortRangeStringToSetDataEnd(t *testing.T) {
	res, err := PortRangeStringToSetData("1234", "bad")
	assert.Error(t, err)
	assert.Equal(t, SetData{}, res)
}

func TestBadPortStringsRangeList(t *testing.T) {
	bad := []string{"-"}

	res, err := PortStringsToSetData(bad)
	assert.Error(t, err)
	assert.Equal(t, []SetData{}, res)
}

func TestBadPortStringsPortList(t *testing.T) {
	bad := []string{"bad"}

	res, err := PortStringsToSetData(bad)
	assert.Error(t, err)
	assert.Equal(t, []SetData{}, res)
}

func TestBadIPNetList(t *testing.T) {
	one := net.IPNet{}
	bad := []*net.IPNet{&one}

	res, err := NetIPNetsToSetData(bad)
	assert.Error(t, err)
	assert.Equal(t, []SetData{}, res)
}

func TestBadIPList(t *testing.T) {
	one := net.IP{}
	bad := []net.IP{one}

	res, err := NetIPsToSetData(bad)
	assert.Error(t, err)
	assert.Equal(t, []SetData{}, res)
}

func TestGoodAddressStringList(t *testing.T) {
	good := []string{
		"198.51.100.200",
		"198.51.100.1-198.51.100.100",
		"203.0.113.100/30",
		"2001:db80:85a3:1:1:8a2e:1370:7334",
		"2001:db80:85a3:1:1:8a2e:1370:7336-2001:db80:85a3:1:1:8a2e:1370:7339",
		"2001:dbb0:1234::/48",
	}

	res, err := AddressStringsToSetData(good)
	assert.Nil(t, err)
	assert.Equal(t, len(good), len(res))
}

func TestGoodPortStringList(t *testing.T) {
	good := []string{
		"8080",
		"1000-2000",
	}

	res, err := PortStringsToSetData(good)
	assert.Nil(t, err)
	assert.Equal(t, len(good), len(res))
}

func TestGoodIPNetList(t *testing.T) {
	_, one, err := net.ParseCIDR("203.0.113.100/30")
	assert.Nil(t, err)

	_, two, err := net.ParseCIDR("2001:dbb0:1234::/48")
	assert.Nil(t, err)

	good := []*net.IPNet{
		one,
		two,
	}

	res, err := NetIPNetsToSetData(good)
	assert.Nil(t, err)
	assert.Equal(t, len(good), len(res))
}

func TestGoodIPList(t *testing.T) {
	one := net.ParseIP("203.0.113.100")
	two := net.ParseIP("2001:dbb0:1234::")

	good := []net.IP{
		one,
		two,
	}

	res, err := NetIPsToSetData(good)
	assert.Nil(t, err)
	assert.Equal(t, len(good), len(res))
}

func TestGoodAddressV4(t *testing.T) {
	one := "203.0.113.100"
	res, err := AddressStringToSetData(one)
	assert.Nil(t, err)

	parsed := netip.MustParseAddr(one)
	assert.Equal(t, res.Address, parsed)
}

func TestGoodAddressV6(t *testing.T) {
	one := "2001:db80:85a3:1:1:8a2e:1370:7334"
	res, err := AddressStringToSetData(one)
	assert.Nil(t, err)

	parsed := netip.MustParseAddr(one)
	assert.Equal(t, res.Address, parsed)
}

func TestGoodRangeAddressV4(t *testing.T) {
	one := "203.0.113.100"
	two := "203.0.113.103"
	res, err := AddressRangeStringToSetData(one, two)
	assert.Nil(t, err)

	parsedOne := netip.MustParseAddr(one)
	parsedTwo := netip.MustParseAddr(two)
	assert.Equal(t, res.AddressRangeStart, parsedOne)
	assert.Equal(t, res.AddressRangeEnd, parsedTwo)
}

func TestGoodAddressRangeV6(t *testing.T) {
	one := "2001:db80:85a3:1:1:8a2e:1370:7334"
	two := "2001:db80:85a3:1:1:8a2e:1370:7339"
	res, err := AddressRangeStringToSetData(one, two)
	assert.Nil(t, err)

	parsedOne := netip.MustParseAddr(one)
	parsedTwo := netip.MustParseAddr(two)
	assert.Equal(t, res.AddressRangeStart, parsedOne)
	assert.Equal(t, res.AddressRangeEnd, parsedTwo)
}

func TestGoodPrefixV4(t *testing.T) {
	one := "203.0.113.100/30"
	res, err := PrefixStringToSetData(one)
	assert.Nil(t, err)

	parsed := netip.MustParsePrefix(one)
	assert.Equal(t, res.Prefix, parsed)
}

func TestGoodPrefixV6(t *testing.T) {
	one := "2001:dbb0:1234::/48"
	res, err := PrefixStringToSetData(one)
	assert.Nil(t, err)

	parsed := netip.MustParsePrefix(one)
	assert.Equal(t, res.Prefix, parsed)
}

func TestGoodPort(t *testing.T) {
	one := "8000"
	res, err := PortStringToSetData(one)
	assert.Nil(t, err)

	assert.Equal(t, res.Port, uint16(8000))
}

func TestGoodPortRange(t *testing.T) {
	one := "8000"
	two := "9000"
	res, err := PortRangeStringToSetData(one, two)
	assert.Nil(t, err)

	assert.Equal(t, res.PortRangeStart, uint16(8000))
	assert.Equal(t, res.PortRangeEnd, uint16(9000))
}

func TestGoodNetipAddressesV4(t *testing.T) {
	one := "203.0.113.100"
	parsed := netip.MustParseAddr(one)
	list := []netip.Addr{parsed}
	res, err := NetipAddrsToSetData(list)
	assert.Nil(t, err)
	assert.Equal(t, res[0].Address, parsed)
}

func TestGoodNetipPrefixesV4(t *testing.T) {
	one := "203.0.113.100/22"
	parsed := netip.MustParsePrefix(one)
	list := []netip.Prefix{parsed}
	res, err := NetipPrefixesToSetData(list)
	assert.Nil(t, err)
	assert.Equal(t, res[0].Prefix, parsed)
}

func TestGoodNetipAddrPortsV4(t *testing.T) {
	one := "203.0.113.100:8080"
	parsed := netip.MustParseAddrPort(one)
	list := []netip.AddrPort{parsed}
	addrs, ports, err := NetipAddrPortsToSetData(list)
	assert.Nil(t, err)
	assert.Equal(t, addrs[0].Address, parsed.Addr())
	assert.Equal(t, ports[0].Port, parsed.Port())
}
