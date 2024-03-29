package rule

import (
	"errors"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
)

type builder struct {
	family    expressions.AddrFamily
	transport expressions.TransportProto
	exprs     []expr.Any
}

// Defines a Match signature for supply matches to rules to it can modify the
// underlying builder and return any errors it encounter when attempting to
// build a rule.
type Match func(*builder) error

// Build requires Verdict, AddrFamily, and TransportProto to build a minimal
// rule for nftables. Optionally, any number of matches can be provided in
// order to increase specificity of the rule. Build will return an error if
// the rule does not make sense. For instance, if you use IPv4 and then attempt
// to provide IPv6 addresses.
func Build(v expr.VerdictKind, matches ...Match) ([]expr.Any, error) {
	b := builder{}

	for _, m := range matches {
		if err := b.with(m); err != nil {
			return nil, err
		}
	}

	// to allow for space for family, transport, and verdict without needing to
	// grow the underlying array since we know the capacity ahead of time
	exprs := make([]expr.Any, 0, len(b.exprs)+3)

	if b.family > 0 {
		exprfamily, err := expressions.CompareProtocolFamily(byte(b.family))
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, exprfamily...)
	}

	if b.transport > 0 {
		exprtransport, err := expressions.CompareTransportProtocol(byte(b.transport))
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, exprtransport...)
	}

	exprs = append(exprs, b.exprs...)

	exprs = append(exprs, &expr.Verdict{Kind: v})

	return exprs, nil
}

func (b *builder) with(opt Match) error {
	if err := opt(b); err != nil {
		return err
	}
	return nil
}

func (b *builder) checkAddrFamily(ip netip.Addr) error {
	if b.family <= 0 {
		return nil
	}
	if (ip.Is4() && b.family != expressions.IPv4) || (ip.Is6() && b.family != expressions.IPv6) {
		return errors.New("rule family and ip family mismatch")
	}
	return nil
}

func (b *builder) checkSetKeyTypeFamily(kt nftables.SetDatatype) error {
	if b.family <= 0 {
		return nil
	}
	if (kt == nftables.TypeIPAddr && b.family != expressions.IPv4) || (kt == nftables.TypeIP6Addr && b.family != expressions.IPv6) {
		return errors.New("rule family and ip family mismatch")
	}
	return nil
}

// Any is a convenience function for adding any number of raw expr.Any types to
// the rule. Use this with caution and if you know how nftables will interpret
// the expressions added.
func Any(e ...expr.Any) Match {
	return func(b *builder) error {
		b.exprs = append(b.exprs, e...)
		return nil
	}
}

// AddressFamily sets the AddrFamily for the rule. This will error if used more
// than once in a single rule since nftables does not support mixing address
// families in a single rule.
func AddressFamily(af expressions.AddrFamily) Match {
	return func(b *builder) error {
		if b.family != 0 {
			return errors.New("family already set")
		}
		b.family = af
		return nil
	}
}

// TransportProtocol sets the TransportProto for the rule. This will error if
// used more than once in a single rule since nftables does not support mixing
// transport protocols in a single rule.
func TransportProtocol(tp expressions.TransportProto) Match {
	return func(b *builder) error {
		if b.transport != 0 {
			return errors.New("transport already already set")
		}
		b.transport = tp
		return nil
	}
}

// SourceAddress adds a single source IP address to the rule to match on.
func SourceAddress(ip netip.Addr) Match {
	return func(b *builder) error {
		if err := b.checkAddrFamily(ip); err != nil {
			return err
		}

		e, err := expressions.CompareSourceAddress(ip)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// SourceAddressSet adds an nftables named set of source IP addresses to match
// on. It ensure this named set already exists in nftables so you don't have
// a rule referencing a non-existant named set.
func SourceAddressSet(set *nftables.Set) Match {
	return func(b *builder) error {
		if err := b.checkSetKeyTypeFamily(set.KeyType); err != nil {
			return err
		}

		e, err := expressions.CompareSourceAddressSet(set)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// SourcePort adds a single source port to the rule to match on.
func SourcePort(port uint16) Match {
	return func(b *builder) error {
		e, err := expressions.CompareSourcePort(port)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// SourcePortSet adds an nftables named set of source ports to match on. It
// ensure this named set already exists in nftables so you don't have a rule
// referencing a non-existant named set.
func SourcePortSet(set *nftables.Set) Match {
	return func(b *builder) error {
		e, err := expressions.CompareSourcePortSet(set)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// DestinationAddress adds a single destination IP address to the rule to match
// on.
func DestinationAddress(ip netip.Addr) Match {
	return func(b *builder) error {
		if err := b.checkAddrFamily(ip); err != nil {
			return err
		}

		e, err := expressions.CompareDestinationAddress(ip)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// DestinationAddressSet adds an nftables named set of destination IP addresses
// to match on. It ensure this named set already exists in nftables so you
// don't have a rule referencing a non-existant named set.
func DestinationAddressSet(set *nftables.Set) Match {
	return func(b *builder) error {
		if err := b.checkSetKeyTypeFamily(set.KeyType); err != nil {
			return err
		}

		e, err := expressions.CompareDestinationAddressSet(set)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// DestinationPort adds a single destination port to the rule to match on.
func DestinationPort(port uint16) Match {
	return func(b *builder) error {
		e, err := expressions.CompareDestinationPort(port)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// DestinationPortSet adds an nftables named set of destination ports to match
// on. It ensure this named set already exists in nftables so you don't have a
// rule referencing a non-existant named set.
func DestinationPortSet(set *nftables.Set) Match {
	return func(b *builder) error {
		e, err := expressions.CompareDestinationPortSet(set)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)

		return nil
	}
}

// ConnectionTrackingState adds the state mask to the rule to match what the
// state the connection should be in to match. You may supply multiple
// values by supplying a bitwise OR set (ex. `StateNew | StateEstablished`)
func ConnectionTrackingState(mask uint32) Match {
	return func(b *builder) error {
		e, err := expressions.CompareCtState(mask)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)
		return nil
	}
}

// LoadConnectionTrackingState loads the key in which the connection tracking
// information should be loaded into the rule.
func LoadConnectionTrackingState(key expr.CtKey) Match {
	return func(b *builder) error {
		e, err := expressions.LoadCtByKey(key)
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e)
		return nil
	}
}
