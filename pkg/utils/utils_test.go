package utils

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePortRange(t *testing.T) {
	err := ValidatePortRange(1, 100)
	assert.Nil(t, err)
}

func TestValidateBadPortRangeStart(t *testing.T) {
	err := ValidatePortRange(-100, 100)
	assert.Error(t, err)
}

func TestValidateBadPortRangeEnd(t *testing.T) {
	err := ValidatePortRange(100, -100)
	assert.Error(t, err)
}

func TestValidateBadPortRangeBeginEnd(t *testing.T) {
	err := ValidatePortRange(101, 100)
	assert.Error(t, err)
}

func TestValidatePort(t *testing.T) {
	err := ValidatePort(1000)
	assert.Nil(t, err)
}

func TestValidateBadPortLow(t *testing.T) {
	err := ValidatePort(0)
	assert.Error(t, err)
}

func TestValidateBadPortHight(t *testing.T) {
	err := ValidatePort(10000000)
	assert.Error(t, err)
}

func TestValidateAddressRange(t *testing.T) {
	start := netip.MustParseAddr("198.51.100.200")
	end := netip.MustParseAddr("198.51.100.205")
	err := ValidateAddressRange(start, end)
	assert.Nil(t, err)
}

func TestValidateBadAddressRangeBeginEnd(t *testing.T) {
	start := netip.MustParseAddr("198.51.100.205")
	end := netip.MustParseAddr("198.51.100.200")
	err := ValidateAddressRange(start, end)
	assert.Error(t, err)
}

func TestValidateBadAddressRangeStart(t *testing.T) {
	start := netip.MustParseAddr("0.0.0.0")
	end := netip.MustParseAddr("198.51.100.200")
	err := ValidateAddressRange(start, end)
	assert.Error(t, err)
}

func TestValidateBadAddressRangeEnd(t *testing.T) {
	start := netip.MustParseAddr("198.51.100.200")
	end := netip.MustParseAddr("0.0.0.0")
	err := ValidateAddressRange(start, end)
	assert.Error(t, err)
}

func TestValidateIP(t *testing.T) {
	ip := netip.MustParseAddr("2001:1db8:85a3:1:1:8a2e:1370:7334")
	err := ValidateAddress(ip)
	assert.Nil(t, err)
}

func TestValidateBadIPZero(t *testing.T) {
	err := ValidateAddress(netip.Addr{})
	assert.Error(t, err)
}

func TestValidateBadIPUnspec(t *testing.T) {
	ip := netip.MustParseAddr("0.0.0.0")
	err := ValidateAddress(ip)
	assert.Error(t, err)
}

func TestValidatePrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:1234::/48")
	err := ValidatePrefix(prefix)
	assert.Nil(t, err)
}

func TestValidateBadPrefix(t *testing.T) {
	err := ValidatePrefix(netip.Prefix{})
	assert.Error(t, err)
}
