package rule

import (
	"errors"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
)

type Verdict expr.VerdictKind

const (
	Return   Verdict = Verdict(expr.VerdictReturn)
	Goto     Verdict = Verdict(expr.VerdictGoto)
	Jump     Verdict = Verdict(expr.VerdictJump)
	Break    Verdict = Verdict(expr.VerdictBreak)
	Continue Verdict = Verdict(expr.VerdictContinue)
	Accept   Verdict = Verdict(expr.VerdictAccept)
	Drop     Verdict = Verdict(expr.VerdictDrop)
	Stolen   Verdict = Verdict(expr.VerdictStolen)
	Queue    Verdict = Verdict(expr.VerdictQueue)
	Repeat   Verdict = Verdict(expr.VerdictRepeat)
	Stop     Verdict = Verdict(expr.VerdictStop)
)

type ConnTrackState uint32

const (
	StateInvalid     ConnTrackState = ConnTrackState(expr.CtStateBitINVALID)
	StateEstablished ConnTrackState = ConnTrackState(expr.CtStateBitESTABLISHED)
	StateRelated     ConnTrackState = ConnTrackState(expr.CtStateBitRELATED)
	StateNew         ConnTrackState = ConnTrackState(expr.CtStateBitNEW)
	StateUntracked   ConnTrackState = ConnTrackState(expr.CtStateBitUNTRACKED)
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
func Build(v Verdict, matches ...Match) ([]expr.Any, error) {
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

	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictKind(v)})

	return exprs, nil
}

func (b *builder) with(opt Match) error {
	if err := opt(b); err != nil {
		return err
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
// ConnTrackState values by supplying a bitwise OR set of values
// (ex. `StateNew | StateEstablished`)
func ConnectionTrackingState(mask ConnTrackState) Match {
	return func(b *builder) error {
		e, err := expressions.CompareCtState(uint32(mask))
		if err != nil {
			return err
		}
		b.exprs = append(b.exprs, e...)
		return nil
	}
}
