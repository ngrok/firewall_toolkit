//go:build linux

/*
A library for managing IP and port nftables sets
*/
package set

import (
	"fmt"
	"sync"

	"github.com/gaissmai/extnetip"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"

	"github.com/ngrok/firewall_toolkit/pkg/utils"
)

// Constants used temporarily while initialzing a set
const (
	// https://datatracker.ietf.org/doc/html/rfc5737#section-3
	InitIPv4 = "192.0.2.1"
	// https://datatracker.ietf.org/doc/html/rfc5156#section-2.6
	InitIPv6 = "2001:0db8:85a3:1:1:8a2e:0370:7334"
	InitPort = "1"
)

// Set represents an nftables a set on a given table
type Set struct {
	set *nftables.Set
	// SetData representation of each of the
	// items currently in the set
	currentSetData map[SetData]struct{}
	mu             *sync.Mutex
}

// Create a new set on a table with a given key type
func New(c *nftables.Conn, table *nftables.Table, name string, keyType nftables.SetDatatype) (Set, error) {
	// we've seen problems where sets need to be initialized with a value otherwise nftables seems to default to the
	// native endianness, likely little endian, which is always incorrect for network stuff resulting in backwards ips, etc.
	// we set everything to documentation values and then immediately delete them leaving empty, correctly created sets.
	var initElems []nftables.SetElement
	switch keyType {
	case nftables.TypeIPAddr:
		ip, err := AddressStringToSetData(InitIPv4)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial port set element %v: %v", InitIPv4, err)
		}

		initElems, err = generateElements(keyType, []SetData{ip})
		if err != nil {
			return Set{}, fmt.Errorf("failed to generate initial ipv4 set element %v: %v", ip, err)
		}
	case nftables.TypeIP6Addr:
		ip, err := AddressStringToSetData(InitIPv6)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial ipv6 set element %v: %v", InitIPv6, err)
		}

		initElems, err = generateElements(keyType, []SetData{ip})
		if err != nil {
			return Set{}, fmt.Errorf("failed to generate initial ipv6 set element: %v: %v", ip, err)
		}
	case nftables.TypeInetService:
		port, err := PortStringToSetData(InitPort)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial port set element %v: %v", InitPort, err)
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

	c.FlushSet(set)

	if err := c.Flush(); err != nil {
		return Set{}, fmt.Errorf("error flushing set %v: %v", name, err)
	}

	return Set{
		set: set,
		mu:  &sync.Mutex{},
	}, nil
}

// Compares incoming set elements with existing set elements and adds/removes the differences
// First return value is true if the set was modified, false if there were no updates
func (s *Set) UpdateElements(c *nftables.Conn, newSetData []SetData) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var modified bool

	// If we haven't initialized CurrentSetData, don't need
	// the update logic, can just add everything
	if s.currentSetData == nil {
		return true, s.ClearAndAddElements(c, newSetData)
	}

	addSetData, removeSetData := s.genSetDataDelta(newSetData)

	// Deletes should always happen first, just in case an incoming setData
	// value replaces a single port/ip with a range that includes that port/ip
	if len(removeSetData) > 0 {
		modified = true

		removeElems, err := generateElements(s.set.KeyType, removeSetData)
		if err != nil {
			return false, fmt.Errorf("generating set elements failed for %v: %v", s.set.Name, err)
		}

		if err = c.SetDeleteElements(s.set, removeElems); err != nil {
			return false, fmt.Errorf("nftables delete set elements failed for %v: %v", s.set.Name, err)
		}

		for _, elem := range removeSetData {
			delete(s.currentSetData, elem)
		}
	}

	if len(addSetData) > 0 {
		modified = true

		addElems, err := generateElements(s.set.KeyType, addSetData)
		if err != nil {
			return false, fmt.Errorf("generating set elements failed for %v: %v", s.set.Name, err)
		}

		if err = c.SetAddElements(s.set, addElems); err != nil {
			return false, fmt.Errorf("nftables add set elements failed for %v: %v", s.set.Name, err)
		}

		for _, elem := range addSetData {
			s.currentSetData[elem] = struct{}{}
		}
	}

	return modified, nil
}

// Remove all elements from the set and then add a list of elements
func (s *Set) ClearAndAddElements(c *nftables.Conn, newSetData []SetData) error {
	c.FlushSet(s.set)
	// Clear/Initialize existing map
	s.currentSetData = make(map[SetData]struct{})

	newElems, err := generateElements(s.set.KeyType, newSetData)
	if err != nil {
		return fmt.Errorf("generating set elements failed for %v: %v", s.set.Name, err)
	}

	// add everything in newSetData to the set
	if err := c.SetAddElements(s.set, newElems); err != nil {
		return fmt.Errorf("nftables add set elements failed for %v: %v", s.set.Name, err)
	}

	for _, elem := range newSetData {
		s.currentSetData[elem] = struct{}{}
	}

	return nil
}

// Get the nftables set associated with this Set
func (s *Set) GetSet() *nftables.Set {
	return s.set
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

// genSetDataDelta generates the "delta" between the incoming and the
// existing values in a Set.
// This shouldn't be called unless you have exclusive access to the Set
func (s *Set) genSetDataDelta(incoming []SetData) (add []SetData, remove []SetData) {
	currentCopy := make(map[SetData]struct{})
	for data := range s.currentSetData {
		currentCopy[data] = struct{}{}
	}

	for _, data := range incoming {
		if _, exists := s.currentSetData[data]; !exists {
			add = append(add, data)
		} else {
			// removing an element from the copy indicates
			// we've seen it in the incoming set data
			delete(currentCopy, data)
		}
	}

	// anything left in currentCopy didn't exist in the
	// incoming set data so it should be deleted
	for data := range currentCopy {
		remove = append(remove, data)
	}

	return
}
