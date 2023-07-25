package rule

import (
	"errors"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"golang.org/x/sys/unix"
)

type Verdict string

const (
	VerdictAccept Verdict = "accept"
	VerdictDrop   Verdict = "drop"
)

type builder struct {
	family    byte
	transport byte

	srcaddrs []expr.Any
	srcports []expr.Any
	dstaddrs []expr.Any
	dstports []expr.Any
	counter  bool
	verdict  Verdict
}

type Match func(*builder) error

func Build(id []byte, matches ...Match) ([]expr.Any, error) {
	b := builder{}

	for _, m := range matches {
		b.with(m)
	}

	exprs := make([]expr.Any, 0)

	exprfamily, err := expressions.CompareProtocolFamily(b.family)
	if err != nil {
		return nil, err
	}

	exprtransport, err := expressions.CompareTransportProtocol(b.transport)
	if err != nil {
		return nil, err
	}

	exprs = append(exprs, exprfamily...)

	exprs = append(exprs, b.srcaddrs...)
	exprs = append(exprs, exprtransport...)
	exprs = append(exprs, b.srcports...)

	exprs = append(exprs, b.dstaddrs...)
	exprs = append(exprs, exprtransport...)
	exprs = append(exprs, b.dstports...)

	if b.counter {
		exprs = append(exprs, expressions.Counter())
	}

	switch b.verdict {
	case VerdictAccept:
		exprs = append(exprs, expressions.Accept())
	case VerdictDrop:
		exprs = append(exprs, expressions.Drop())
	}

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

func IPv4() Match {
	return func(b *builder) error {
		if b.family != 0 {
			return errors.New("family already set")
		}
		b.family = unix.NFPROTO_IPV4
		return nil
	}
}

func IPv6() Match {
	return func(b *builder) error {
		if b.transport != 0 {
			return errors.New("family already set")
		}
		b.family = unix.NFPROTO_IPV6
		return nil
	}
}

func TCP() Match {
	return func(b *builder) error {
		if b.transport != 0 {
			return errors.New("transport already set")
		}
		b.transport = unix.IPPROTO_TCP
		return nil
	}
}

func UDP() Match {
	return func(b *builder) error {
		if b.transport != 0 {
			return errors.New("transport already set")
		}
		b.transport = unix.IPPROTO_UDP
		return nil
	}
}

func Counter() Match {
	return func(b *builder) error {
		b.counter = true
		return nil
	}
}

func Statement(v Verdict) Match {
	return func(b *builder) error {
		b.verdict = v
		return nil
	}
}

func SourceAddress(ip netip.Addr) Match {
	return func(b *builder) error {
		if err := b.checkAddrFamily(ip); err != nil {
			return err
		}

		if ip.Is4() {
			b.with(IPv4())
		} else if ip.Is6() {
			b.with(IPv6())
		}

		var err error
		b.srcaddrs, err = expressions.CompareSourceAddress(ip)
		if err != nil {
			return err
		}

		return nil
	}
}

func SourceAddressSet(set *nftables.Set) Match {
	return func(b *builder) error {
		if err := b.checkSetDatatypeFamily(set.KeyType); err != nil {
			return err
		}

		switch set.KeyType {
		case nftables.TypeIPAddr:
			b.with(IPv4())
		case nftables.TypeIP6Addr:
			b.with(IPv6())
		}

		var err error
		b.srcaddrs, err = expressions.CompareSourceAddressSet(set)
		if err != nil {
			return err
		}

		return nil
	}
}

func SourcePort(port uint16) Match {
	return func(b *builder) error {
		var err error
		b.srcports, err = expressions.CompareSourcePort(port)
		if err != nil {
			return err
		}

		return nil
	}
}

func SourcePortSet(set *nftables.Set) Match {
	return func(b *builder) error {
		var err error
		b.srcports, err = expressions.CompareSourcePortSet(set)
		if err != nil {
			return err
		}

		return nil
	}
}

func DestinationAddress(ip netip.Addr) Match {
	return func(b *builder) error {
		if err := b.checkAddrFamily(ip); err != nil {
			return err
		}

		if ip.Is4() {
			b.with(IPv4())
		} else if ip.Is6() {
			b.with(IPv6())
		}

		var err error
		b.dstaddrs, err = expressions.CompareDestinationAddress(ip)
		if err != nil {
			return err
		}

		return nil
	}
}

func DestinationAddressSet(set *nftables.Set) Match {
	return func(b *builder) error {
		if err := b.checkSetDatatypeFamily(set.KeyType); err != nil {
			return err
		}

		switch set.KeyType {
		case nftables.TypeIPAddr:
			b.with(IPv4())
		case nftables.TypeIP6Addr:
			b.with(IPv6())
		}

		var err error
		b.dstaddrs, err = expressions.CompareDestinationAddressSet(set)
		if err != nil {
			return err
		}

		return nil
	}
}

func DestinationPort(port uint16) Match {
	return func(b *builder) error {
		var err error
		b.dstports, err = expressions.CompareDestinationPort(port)
		if err != nil {
			return err
		}

		return nil
	}
}

func DestinationPortSet(set *nftables.Set) Match {
	return func(b *builder) error {
		var err error
		b.dstports, err = expressions.CompareDestinationPortSet(set)
		if err != nil {
			return err
		}

		return nil
	}
}
