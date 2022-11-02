package set

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// SetData is a struct that is used to create elements of a given set based on the key type of the set
type SetData struct {
	Port              int
	PortRangeStart    int
	PortRangeEnd      int
	Address           netip.Addr
	AddressRangeStart netip.Addr
	AddressRangeEnd   netip.Addr
	Prefix            netip.Prefix
}

// Convert a string address to the SetData type
func AddressStringToSetData(addressString string) (SetData, error) {
	address, err := netip.ParseAddr(addressString)
	if err != nil {
		return SetData{}, err
	}

	return SetData{Address: address}, nil
}

// Convert a string prefix/CIDR to the SetData type
func PrefixStringToSetData(prefixString string) (SetData, error) {
	prefix, err := netip.ParsePrefix(prefixString)
	if err != nil {
		return SetData{}, err
	}

	return SetData{Prefix: prefix}, nil
}

// Convert a string address range to the SetData type
func AddressRangeStringToSetData(startString string, endString string) (SetData, error) {
	start, err := netip.ParseAddr(startString)
	if err != nil {
		return SetData{}, err
	}

	end, err := netip.ParseAddr(endString)
	if err != nil {
		return SetData{}, err
	}

	return SetData{
		AddressRangeStart: start,
		AddressRangeEnd:   end,
	}, nil
}

// Convert a list of string addresses to the SetData type
func AddressStringsToSetData(addressStrings []string) ([]SetData, error) {
	data := []SetData{}

	for _, addressString := range addressStrings {
		if strings.Contains(addressString, "/") {
			// if it includes / we assume prefix i.e. 4.4.4.4/32
			prefix, err := PrefixStringToSetData(addressString)
			if err != nil {
				return data, err
			}
			data = append(data, prefix)
			continue
		}
		if strings.Contains(addressString, "-") {
			// if it includes - we assume a range i.e. 10.10.10.10-10.10.10.15
			split := strings.Split(addressString, "-")
			addressRange, err := AddressRangeStringToSetData(split[0], split[1])
			if err != nil {
				return data, err
			}
			data = append(data, addressRange)
			continue
		}
		// if we get here assume its just a normal IP i.e. 1.1.1.1
		address, err := AddressStringToSetData(addressString)
		if err != nil {
			return data, err
		}
		data = append(data, address)

	}

	return data, nil
}

// Convert a string port to the SetData type
func PortStringToSetData(portString string) (SetData, error) {
	port, err := strconv.Atoi(portString)
	if err != nil {
		return SetData{}, err
	}

	return SetData{Port: port}, nil
}

// Convert a string port range to the SetData type
func PortRangeStringToSetData(startString string, endString string) (SetData, error) {
	start, err := strconv.Atoi(startString)
	if err != nil {
		return SetData{}, err
	}

	end, err := strconv.Atoi(endString)
	if err != nil {
		return SetData{}, err
	}

	return SetData{
		PortRangeStart: start,
		PortRangeEnd:   end,
	}, nil
}

// Convert a list string ports to the SetData type
func PortStringsToSetData(portStrings []string) ([]SetData, error) {
	data := []SetData{}

	for _, portString := range portStrings {
		if strings.Contains(portString, "-") {
			// if it includes - we assume a range i.e. 10000-30000
			split := strings.Split(portString, "-")
			portRange, err := PortRangeStringToSetData(split[0], split[1])
			if err != nil {
				return data, err
			}
			data = append(data, portRange)
		} else {
			// assume its just a normal port i.e. 80
			port, err := PortStringToSetData(portString)
			if err != nil {
				return data, err
			}
			data = append(data, port)
		}
	}

	return data, nil
}

// Convert net.IPNet to the SetData type
func IPNetToSetData(net *net.IPNet) (SetData, error) {
	ones, _ := net.Mask.Size()
	ip, ok := netip.AddrFromSlice(net.IP)

	if !ok {
		return SetData{}, fmt.Errorf("could not parse %v", net.String())
	}

	return SetData{Prefix: netip.PrefixFrom(ip, ones)}, nil
}

// Convert a list of net.IPNet to the SetData type
func IPNetsToSetData(nets []*net.IPNet) ([]SetData, error) {
	data := []SetData{}

	for _, net := range nets {
		prefix, err := IPNetToSetData(net)
		if err != nil {
			return data, err
		}
		data = append(data, prefix)
	}

	return data, nil
}

// Convert net.IP to the SetData type
func IPToSetData(ip net.IP) (SetData, error) {
	netip, ok := netip.AddrFromSlice(ip)
	if !ok {
		return SetData{}, fmt.Errorf("could not parse ip: %v", ip)
	}

	return SetData{Address: netip}, nil
}

// Convert a list of net.IP to the SetData type
func IPsToSetData(ips []net.IP) ([]SetData, error) {
	data := []SetData{}

	for _, ip := range ips {
		netip, err := IPToSetData(ip)
		if err != nil {
			return data, err
		}
		data = append(data, netip)
	}

	return data, nil
}
