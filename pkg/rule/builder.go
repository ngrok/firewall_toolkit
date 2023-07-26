package rule

import (
	"errors"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"golang.org/x/sys/unix"
)

type AddrFamily int8

const (
	AnyFamily AddrFamily = unix.NFPROTO_INET
	IPv4      AddrFamily = unix.NFPROTO_IPV4
	IPv6      AddrFamily = unix.NFPROTO_IPV6
)

type TransportProto int8

const (
	AnyTransport TransportProto = -1
	TCP          TransportProto = unix.IPPROTO_TCP
	UDP          TransportProto = unix.IPPROTO_UDP
)

type Verdict expr.VerdictKind

const (
	Accept Verdict = Verdict(expr.VerdictAccept)
	Drop   Verdict = Verdict(expr.VerdictDrop)
)

type builder struct {
	family    byte
	transport byte
	verdict   expr.VerdictKind

	exprs []expr.Any
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
func Build(v Verdict, af AddrFamily, tp TransportProto, matches ...Match) ([]expr.Any, error) {
	b := builder{}

	for _, m := range matches {
		b.with(m)
	}

	exprs := make([]expr.Any, 0)

	exprfamily, err := expressions.CompareProtocolFamily(b.family)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, exprfamily...)

	if b.transport > 0 {
		exprtransport, err := expressions.CompareTransportProtocol(b.transport)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, exprtransport...)
	}

	exprs = append(exprs, b.exprs...)

	exprs = append(exprs, &expr.Verdict{Kind: b.verdict})

	return exprs, nil
}

func (b *builder) with(opt Match) error {
	if err := opt(b); err != nil {
		return err
	}
	return nil
}

func (b *builder) checkAddrFamily(ip netip.Addr) error {
	if ip.Is4() && b.family == unix.NFPROTO_IPV6 {
		return errors.New("family and ip mismatch")
	}
	if ip.Is6() && b.family == unix.NFPROTO_IPV4 {
		return errors.New("family and ip mismatch")
	}
	return nil
}

func (b *builder) checkSetDatatypeFamily(family nftables.SetDatatype) error {
	switch family {
	case nftables.TypeIPAddr:
		if b.family == unix.NFPROTO_IPV6 {
			return errors.New("family and ip mismatch")
		}
	case nftables.TypeIP6Addr:
		if b.family == unix.NFPROTO_IPV4 {
			return errors.New("family and ip mismatch")
		}
	}
	return nil
}

// Counter adds the "counter" expression to the rule to keep track of the
// the number of bytes and packets the rule matches on traffic.
func Counter() Match {
	return func(b *builder) error {
		b.exprs = append(b.exprs, expressions.Counter())
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
		if err := b.checkSetDatatypeFamily(set.KeyType); err != nil {
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
		if err := b.checkSetDatatypeFamily(set.KeyType); err != nil {
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
