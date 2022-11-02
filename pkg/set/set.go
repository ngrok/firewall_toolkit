//go:build linux

/*
A library for managing IP and port nftables sets
*/
package set

import (
	"fmt"

	"github.com/gaissmai/extnetip"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"

	"github.com/ngrok/firewall_toolkit/pkg/utils"
)

// Constants used temporarily while initialzing a set
const (
	// https://datatracker.ietf.org/doc/html/rfc5737#section-3
	InitIPV4 = "192.0.2.1"
	// https://datatracker.ietf.org/doc/html/rfc5156#section-2.6
	InitIPV6 = "2001:0db8:85a3:1:1:8a2e:0370:7334"
	InitPORT = "1"
)

// Set represents an nftables netlink connection and a set on a given table
type Set struct {
	Conn *nftables.Conn
	Set  *nftables.Set
}

// Create a new set on a table with a given key type
func New(name string, c *nftables.Conn, table *nftables.Table, keyType nftables.SetDatatype) (Set, error) {
	// sets need to be initialized with a value otherwise nftables seems to default to the
	// native endianness (likely little endian) which is incorrect for ips, ports, etc
	// we set everything to documentation values and then immediately delete them leaving empty, correctly created sets
	var initElems []nftables.SetElement
	switch keyType {
	case nftables.TypeIPAddr:
		ip, err := AddressStringToSetData(InitIPV4)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial port set element %v: %v", InitIPV4, err)
		}

		initElems, err = generateElements(keyType, []SetData{ip})
		if err != nil {
			return Set{}, fmt.Errorf("failed to generate initial ipv4 set element %v: %v", ip, err)
		}
	case nftables.TypeIP6Addr:
		ip, err := AddressStringToSetData(InitIPV6)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial ipv6 set element %v: %v", InitIPV6, err)
		}

		initElems, err = generateElements(keyType, []SetData{ip})
		if err != nil {
			return Set{}, fmt.Errorf("failed to generate initial ipv6 set element: %v: %v", ip, err)
		}
	case nftables.TypeInetService:
		port, err := PortStringToSetData(InitPORT)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial port set element %v: %v", InitPORT, err)
		}

		initElems, err = generateElements(keyType, []SetData{port})
		if err != nil {
			return Set{}, fmt.Errorf("failed to generate initial port set element: %v: %v", port, err)
		}
	default:
		return Set{}, fmt.Errorf("unsupported set key type: %v", keyType)
	}

	set := &nftables.Set{
		Name:     name,
		Table:    table,
		KeyType:  keyType,
		Interval: true,
		Counter:  true,
	}

	if err := c.AddSet(set, initElems); err != nil {
		return Set{}, fmt.Errorf("nftables set init failed for %v: %v", name, err)
	}

	if err := c.Flush(); err != nil {
		return Set{}, fmt.Errorf("error flushing set %v: %v", name, err)
	}

	return Set{
		Conn: c,
		Set:  set,
	}, nil
}

// Compares incoming set elements with existing set elements and adds/removes the differences
func (s *Set) UpdateElements(newSetData []SetData) error {
	// FIXME: we should be smarter about removing diffs from the sets
	// we loose counters when we flush the whole set, etc
	// ideally we'd collapse contiguous ranges, sort and delete beginning and ending intervals appropriately
	// probably need to keep track of the previous []SetData to do that
	// for now we flush the set because we always know it's correct
	return fmt.Errorf("unimplemented")
}

// Remove all elements from the set and then add a list of elements
func (s *Set) ClearAndAddElements(newSetData []SetData) error {
	s.Conn.FlushSet(s.Set)

	newElems, err := generateElements(s.Set.KeyType, newSetData)
	if err != nil {
		return fmt.Errorf("generating set elements failed for %v: %v", s.Set.Name, err)
	}

	// add everything in newSetData to the set
	if err := s.Conn.SetAddElements(s.Set, newElems); err != nil {
		return fmt.Errorf("nftables add set elements failed for %v: %v", s.Set.Name, err)
	}

	// flush it
	if err := s.Conn.Flush(); err != nil {
		return fmt.Errorf("error flushing set %v with new elements %v: %v", s.Set.Name, newElems, err)
	}

	return nil
}

func generateElements(keyType nftables.SetDatatype, list []SetData) ([]nftables.SetElement, error) {
	// we use interval sets for everything so we have a common set to build on top of
	// due to this for each set type we need to generate start and ends of each interval even for single IPs
	elems := []nftables.SetElement{}
	for _, e := range list {
		toAppend := []nftables.SetElement{}
		switch keyType {
		case nftables.TypeIPAddr:
			if err := validateSetDataAddresses(e); err != nil {
				return []nftables.SetElement{}, err
			}

			if e.AddressRangeStart.Is4() && e.AddressRangeEnd.Is4() {
				toAppend = []nftables.SetElement{
					{Key: e.AddressRangeStart.AsSlice()},
					{Key: e.AddressRangeEnd.Next().AsSlice(),
						IntervalEnd: true},
				}
			} else if e.Address.Is4() {
				toAppend = []nftables.SetElement{
					{Key: e.Address.AsSlice()},
					{Key: e.Address.Next().AsSlice(),
						IntervalEnd: true},
				}
			} else if e.Prefix.Addr().Is4() {
				start, end := extnetip.Range(e.Prefix)
				if err := utils.ValidateAddressRange(start, end); err != nil {
					return []nftables.SetElement{}, err
				}
				toAppend = []nftables.SetElement{
					{Key: start.AsSlice()},
					{Key: end.Next().AsSlice(),
						IntervalEnd: true},
				}
			}
		case nftables.TypeIP6Addr:
			if err := validateSetDataAddresses(e); err != nil {
				return []nftables.SetElement{}, err
			}

			if e.AddressRangeStart.Is6() && e.AddressRangeEnd.Is6() {
				toAppend = []nftables.SetElement{
					{Key: e.AddressRangeStart.AsSlice()},
					{Key: e.AddressRangeEnd.Next().AsSlice(),
						IntervalEnd: true},
				}
			} else if e.Address.Is6() {
				toAppend = []nftables.SetElement{
					{Key: e.Address.AsSlice()},
					{Key: e.Address.Next().AsSlice(),
						IntervalEnd: true},
				}
			} else if e.Prefix.Addr().Is6() {
				start, end := extnetip.Range(e.Prefix)
				if err := utils.ValidateAddressRange(start, end); err != nil {
					return []nftables.SetElement{}, err
				}
				toAppend = []nftables.SetElement{
					{Key: start.AsSlice()},
					{Key: end.Next().AsSlice(),
						IntervalEnd: true},
				}
			}
		case nftables.TypeInetService:
			if err := validateSetDataPorts(e); err != nil {
				return []nftables.SetElement{}, err
			}

			if e.PortRangeStart != 0 && e.PortRangeEnd != 0 {
				toAppend = []nftables.SetElement{
					{Key: binaryutil.BigEndian.PutUint16(uint16(e.PortRangeStart))},
					{Key: binaryutil.BigEndian.PutUint16(uint16(e.PortRangeEnd + 1)),
						IntervalEnd: true},
				}
			} else if e.Port != 0 {
				toAppend = []nftables.SetElement{
					{Key: binaryutil.BigEndian.PutUint16(uint16(e.Port))},
					{Key: binaryutil.BigEndian.PutUint16(uint16(e.Port + 1)),
						IntervalEnd: true},
				}
			}
		default:
			return []nftables.SetElement{}, fmt.Errorf("unsupported set key type %v", keyType)
		}

		elems = append(elems, toAppend...)
	}

	return elems, nil
}

func validateSetDataAddresses(setData SetData) error {
	if setData.AddressRangeStart.IsValid() || setData.AddressRangeEnd.IsValid() {
		if setData.Address.IsValid() {
			return fmt.Errorf("address range and an address can't be set at the same time: %v", setData)
		}

		if setData.Prefix.IsValid() {
			return fmt.Errorf("address range and a prefix can't be set at the same time: %v", setData)
		}
	}

	if setData.Address.IsValid() && setData.Prefix.IsValid() {
		return fmt.Errorf("address and prefix can't be set at the same time: %v", setData)
	}

	if setData.AddressRangeStart.IsValid() && setData.AddressRangeEnd.IsValid() {
		return utils.ValidateAddressRange(setData.AddressRangeStart, setData.AddressRangeEnd)
	} else if setData.Address.IsValid() {
		return utils.ValidateAddress(setData.Address)
	} else if setData.Prefix.IsValid() {
		return utils.ValidatePrefix(setData.Prefix)
	} else {
		return fmt.Errorf("invalid set data: %v", setData)
	}
}

func validateSetDataPorts(setData SetData) error {
	if setData.PortRangeStart != 0 || setData.PortRangeEnd != 0 {
		if setData.Port != 0 {
			return fmt.Errorf("port range and a port can't be set at the same time: %v", setData)
		}
	}

	if setData.PortRangeStart != 0 && setData.PortRangeEnd != 0 {
		return utils.ValidatePortRange(setData.PortRangeStart, setData.PortRangeEnd)
	} else if setData.Port != 0 {
		return utils.ValidatePort(setData.Port)
	} else {
		return fmt.Errorf("invalid set data: %v", setData)
	}
}
