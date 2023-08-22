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
	initIPv4 = "192.0.2.1"
	// https://datatracker.ietf.org/doc/html/rfc5156#section-2.6
	initIPv6 = "2001:0db8:85a3:1:1:8a2e:0370:7334"
	initPort = "1"
)

// Set represents an nftables a set on a given table
type Set struct {
	set *nftables.Set
}

// Create a new set on a table with a given key type
func New(c *nftables.Conn, table *nftables.Table, name string, keyType nftables.SetDatatype) (Set, error) {
	// we've seen problems where sets need to be initialized with a value otherwise nftables seems to default to the
	// native endianness, likely little endian, which is always incorrect for network stuff resulting in backwards ips, etc.
	// we set everything to documentation values and then immediately delete them leaving empty, correctly created sets.
	var initElems []nftables.SetElement
	switch keyType {
	case nftables.TypeIPAddr:
		ip, err := AddressStringToSetData(initIPv4)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial port set element %v: %v", initIPv4, err)
		}

		initElems, err = generateElements(keyType, []SetData{ip})
		if err != nil {
			return Set{}, fmt.Errorf("failed to generate initial ipv4 set element %v: %v", ip, err)
		}
	case nftables.TypeIP6Addr:
		ip, err := AddressStringToSetData(initIPv6)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial ipv6 set element %v: %v", initIPv6, err)
		}

		initElems, err = generateElements(keyType, []SetData{ip})
		if err != nil {
			return Set{}, fmt.Errorf("failed to generate initial ipv6 set element: %v: %v", ip, err)
		}
	case nftables.TypeInetService:
		port, err := PortStringToSetData(initPort)
		if err != nil {
			return Set{}, fmt.Errorf("failed to parse initial port set element %v: %v", initPort, err)
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
	}, nil
}

// Compares incoming set elements with existing set elements and adds/removes the differences.
//
// First return value is true if the set was modified, false if there were no updates. The second
// and third return values indicate the number of values added and removed from the set, respectively.
func (s *Set) UpdateElements(c *nftables.Conn, newSetData []SetData) (bool, int, int, error) {
	var modified bool

	currentSetData, err := s.GetSetElements(c)
	if err != nil {
		return false, 0, 0, err
	}

	addSetData, removeSetData := genSetDataDelta(currentSetData, newSetData)

	// Deletes should always happen first, just in case an incoming setData
	// value replaces a single port/ip with a range that includes that port/ip
	if len(removeSetData) > 0 {
		modified = true

		removeElems, err := generateElements(s.set.KeyType, removeSetData)
		if err != nil {
			return false, 0, 0, fmt.Errorf("generating set elements failed for %v: %v", s.set.Name, err)
		}

		if err = c.SetDeleteElements(s.set, removeElems); err != nil {
			return false, 0, 0, fmt.Errorf("nftables delete set elements failed for %v: %v", s.set.Name, err)
		}
	}

	if len(addSetData) > 0 {
		modified = true

		addElems, err := generateElements(s.set.KeyType, addSetData)
		if err != nil {
			return false, 0, 0, fmt.Errorf("generating set elements failed for %v: %v", s.set.Name, err)
		}

		if err = c.SetAddElements(s.set, addElems); err != nil {
			return false, 0, 0, fmt.Errorf("nftables add set elements failed for %v: %v", s.set.Name, err)
		}
	}

	return modified, len(addSetData), len(removeSetData), nil
}

// Remove all elements from the set and then add a list of elements
func (s *Set) ClearAndAddElements(c *nftables.Conn, newSetData []SetData) error {
	c.FlushSet(s.set)

	newElems, err := generateElements(s.set.KeyType, newSetData)
	if err != nil {
		return fmt.Errorf("generating set elements failed for %v: %v", s.set.Name, err)
	}

	// add everything in newSetData to the set
	if err := c.SetAddElements(s.set, newElems); err != nil {
		return fmt.Errorf("nftables add set elements failed for %v: %v", s.set.Name, err)
	}

	return nil
}

// Get the nftables set associated with this Set
func (s *Set) GetSet() *nftables.Set {
	return s.set
}

// Get all elements associated with this Set
func (s *Set) GetSetElements(c *nftables.Conn) ([]SetData, error) {
	elements, err := c.GetSetElements(s.set)
	if err != nil {
		return nil, err
	}

	switch s.set.KeyType {
	case nftables.TypeIPAddr:
		fallthrough
	case nftables.TypeIP6Addr:
		return addrSetData(elements)
	case nftables.TypeInetService:
		return portSetData(elements)
	default:
		return nil, fmt.Errorf("unexpected set key type: %v", s.set.KeyType)
	}
}

func portSetData(elements []nftables.SetElement) ([]SetData, error) {
	setDataList := []SetData{}

	// set elements come in pairs, first the end of range, then start of range which contains counters
	for i := 0; i < len(elements); i++ {
		startElement, endElement, err := nextRangeElements(elements, &i)
		if err != nil {
			return nil, err
		}

		setData, err := PortBytesToSetData(startElement.Key, endElement.Key)
		if err != nil {
			return nil, err
		}

		setData.bytes = startElement.Counter.Bytes
		setData.packets = startElement.Counter.Packets

		setDataList = append(setDataList, setData)
	}

	return setDataList, nil
}

func addrSetData(elements []nftables.SetElement) ([]SetData, error) {
	setDataList := []SetData{}

	// set elements come in pairs, first the end of range, then start of range which contains counters
	for i := 0; i < len(elements); i++ {
		startElement, endElement, err := nextRangeElements(elements, &i)
		if err != nil {
			return nil, err
		}

		setData, err := AddressBytesToSetData(startElement.Key, endElement.Key)
		if err != nil {
			return nil, err
		}

		setData.bytes = startElement.Counter.Bytes
		setData.packets = startElement.Counter.Packets

		setDataList = append(setDataList, setData)
	}

	return setDataList, nil
}

func nextRangeElements(elements []nftables.SetElement, i *int) (start nftables.SetElement, end nftables.SetElement, err error) {
	if (*i + 1) >= (len(elements)) {
		return nftables.SetElement{}, nftables.SetElement{}, fmt.Errorf("index out of bounds getting range elements")
	}

	endElement := elements[*i]
	if !endElement.IntervalEnd {
		return nftables.SetElement{}, nftables.SetElement{}, fmt.Errorf("expected set element to be an interval end: %+v", endElement)
	}

	*i++
	startElement := elements[*i]
	if startElement.IntervalEnd {
		return nftables.SetElement{}, nftables.SetElement{}, fmt.Errorf("expected set element not to be an interval end: %+v", startElement)
	}

	return startElement, endElement, nil
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
func genSetDataDelta(current []SetData, incoming []SetData) (add []SetData, remove []SetData) {
	currentCopy := make(map[SetData]struct{})

	for _, data := range current {
		currentCopy[data] = struct{}{}
	}

	for _, data := range incoming {
		if _, exists := currentCopy[data]; !exists {
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
