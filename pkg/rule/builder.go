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
	AnyFamily AddrFamily = -1
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

type Match func(*builder) error

func MatchExpressions(v Verdict, af AddrFamily, tp TransportProto, matches ...Match) ([]expr.Any, error) {
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

	exprtransport, err := expressions.CompareTransportProtocol(b.transport)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, exprtransport...)

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

func Counter() Match {
	return func(b *builder) error {
		b.exprs = append(b.exprs, expressions.Counter())
		return nil
	}
}

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
