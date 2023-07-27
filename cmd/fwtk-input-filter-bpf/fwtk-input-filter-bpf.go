//go:build linux && !arm && !arm64

/*
fwtk-input-filter-bpf is a utility that loads bpf into nftables

Usage:

	sudo ~/go/bin/fwtk-input-filter-bpf [flags]

Flags:

	-chain=<chain name>
	-table=<table name>
	-filter=<bpf path | tcpdump-style filter string | socket file descriptor>

The command will load the filter in whatever format specified into a XT BPF Match
rule in the nftables table and chain specified.
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/nftables"

	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/ngrok/firewall_toolkit/pkg/logger"
	"github.com/ngrok/firewall_toolkit/pkg/rule"
	"github.com/ngrok/firewall_toolkit/pkg/xtables"
)

func main() {
	table := flag.String("table", "", "nftables table name")
	chain := flag.String("chain", "", "nftables chain name")
	filter := flag.String("filter", "", "tcpdump-style bpf filter, pinned bpf program path or socket fd")
	verdict := flag.String("verdict", "drop", "nftables verdict (drop, accept, etc")
	flag.Parse()

	exists := []bool{}
	flag.VisitAll(func(f *flag.Flag) {
		if len(f.Value.String()) > 0 {
			exists = append(exists, true)
		}
	})

	if len(exists) != 4 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	c, err := nftables.New()
	if err != nil {
		logger.Default.Fatalf("nftables connection failed: %v", err)
	}

	nfTable := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   *table,
	})

	nfChain := c.AddChain(&nftables.Chain{
		Name:     *chain,
		Table:    nfTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	if err := c.Flush(); err != nil {
		logger.Default.Fatalf("nftables flush failed: %v", err)
	}

	nfVerdict, err := getVerdict(*verdict)
	if err != nil {
		logger.Default.Fatal(err)
	}

	xtBpfInfoBytes, err := getXtBpfInfoBytes(*filter)
	if err != nil {
		logger.Default.Fatal(err)
	}

	exprs, err := rule.Build(
		nfVerdict,
		rule.Any(expressions.MatchBpf(xtBpfInfoBytes)),
	)
	if err != nil {
		logger.Default.Fatal(err)
	}

	ruleTarget := rule.NewRuleTarget(nfTable, nfChain)
	bpfRule := rule.NewRuleData([]byte{0xd, 0xe, 0xa, 0xd}, exprs)
	added, err := ruleTarget.Add(c, bpfRule)
	if err != nil {
		logger.Default.Fatalf("adding rule %x failed: %v", bpfRule.ID, err)
	}

	if added {
		if err := c.Flush(); err != nil {
			logger.Default.Fatalf("nftables flush failed: %v", err)
		}
		logger.Default.Infof("rule %x added", bpfRule.ID)
	} else {
		logger.Default.Infof("rule %x already exists", bpfRule.ID)
	}

}

func getVerdict(verdict string) (rule.Verdict, error) {
	switch verdict {
	case "drop":
		return rule.Drop, nil
	case "accept":
		return rule.Accept, nil
	default:
		return 0, fmt.Errorf("unsupported verdict %v", verdict)
	}
}

func getXtBpfInfoBytes(filter string) ([]byte, error) {
	fd, err := strconv.ParseInt(filter, 10, 32)
	if err == nil {
		xtBpfInfoBytes, err := xtables.MarshalBpfFd(int32(fd))

		if err != nil {
			return []byte{}, err
		}

		return xtBpfInfoBytes, nil
	}

	if strings.HasPrefix(filter, "/") {
		xtBpfInfoBytes, err := xtables.MarshalBpfPinned(filter)

		if err != nil {
			return []byte{}, err
		}

		return xtBpfInfoBytes, nil
	} else {
		xtBpfInfoBytes, err := xtables.MarshalBpfBytecode(filter)

		if err != nil {
			return []byte{}, err
		}

		return xtBpfInfoBytes, nil
	}
}
