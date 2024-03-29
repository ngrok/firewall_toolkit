//go:build linux

/*
fwtk-input-filter-sets is a utility that manages nftables sets and rules

Usage:

	sudo ~/go/bin/fwtk-input-filter-sets [flags]

Flags:

	-chain=<chain name>
	-table=<table name>
	-mode=<oneshot (default) | manager>
	-iplist=<path>
	-portlist=<path>

This command will create a inet table, chain and sets using the names and files specified by the flags above.
The files can contain IPs, CIDRs, ports and ranges, see tests/*.list for examples.
Manager mode will run continuously re-reading the files on a timer.
*/
package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sync/errgroup"

	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/ngrok/firewall_toolkit/pkg/logger"
	"github.com/ngrok/firewall_toolkit/pkg/rule"
	"github.com/ngrok/firewall_toolkit/pkg/set"
)

const (
	RefreshInterval = 1000 * time.Millisecond
)

func main() {
	table := flag.String("table", "", "nftables table name")
	chain := flag.String("chain", "", "nftables chain name")
	mode := flag.String("mode", "oneshot", "oneshot or manager")
	ipFile := flag.String("iplist", "./ip.list", "file containing list of ips")
	portFile := flag.String("portlist", "./port.list", "file containing list of ports")

	flag.Parse()

	exists := []bool{}
	flag.VisitAll(func(f *flag.Flag) {
		if len(f.Value.String()) > 0 {
			exists = append(exists, true)
		}
	})

	if len(exists) != 5 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	c, err := nftables.New()
	if err != nil {
		logger.Default.Fatalf("nftables connection failed: %v", err)
	}

	nfTable := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
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
		logger.Default.Fatalf("add table and chain flush failed: %v", err)
	}

	// create all the sets you plan to use
	ipv4Set, err := set.New(c, nfTable, "ipv4_blocklist", nftables.TypeIPAddr)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	ipv6Set, err := set.New(c, nfTable, "ipv6_blocklist", nftables.TypeIP6Addr)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	portSet, err := set.New(c, nfTable, "port_blocklist", nftables.TypeInetService)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	// get the lists of things to add to the sets
	ipSource := newSource(*ipFile)
	ipList, err := ipSource.getIPList()
	if err != nil {
		logger.Default.Fatalf("error getting ip block list: %v", err)
	}

	portSource := newSource(*portFile)
	portList, err := portSource.getPortList()
	if err != nil {
		logger.Default.Fatalf("error getting port block list: %v", err)
	}

	// put everything in the sets
	if err := ipv4Set.ClearAndAddElements(c, ipList); err != nil {
		logger.Default.Fatalf("failed to update ipv4 set elements: %v", err)
	}

	if err := ipv6Set.ClearAndAddElements(c, ipList); err != nil {
		logger.Default.Fatalf("failed to update ipv6 set elements: %v", err)
	}

	if err := portSet.ClearAndAddElements(c, portList); err != nil {
		logger.Default.Fatalf("failed to update port set elements: %v", err)
	}

	if err := c.Flush(); err != nil {
		logger.Default.Fatalf("add elements flush failed: %v", err)
	}

	ruleTarget := rule.NewRuleTarget(nfTable, nfChain)

	ruleInfo := newRuleInfo(portSet.Set(), ipv4Set.Set(), ipv6Set.Set())

	ruleData, err := ruleInfo.createRuleData()
	if err != nil {
		logger.Default.Fatalf("failed to create rules: %v", err)
	}

	flush := false
	for _, rD := range ruleData {
		added, err := ruleTarget.Add(c, rD)
		if err != nil {
			logger.Default.Fatalf("adding rule %x failed: %v", rD.ID, err)
		}

		if added {
			logger.Default.Infof("rule %x added", rD.ID)
			flush = true
		} else {
			logger.Default.Infof("rule %x already exists", rD.ID)
		}
	}

	if flush {
		if err := c.Flush(); err != nil {
			logger.Default.Fatalf("add rules flush failed: %v", err)
		}
	}

	// manager mode will keep running refreshing sets based on what's in the files
	if *mode == "manager" {
		ctx, cancel := context.WithCancel(context.Background())
		eg, gctx := errgroup.WithContext(ctx)
		defer cancel()

		ipv4SetManager, err := set.ManagerInit(
			ipv4Set,
			ipSource.getIPList,
			RefreshInterval,
			logger.Default,
			nil,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		ipv6SetManager, err := set.ManagerInit(
			ipv6Set,
			ipSource.getIPList,
			RefreshInterval,
			logger.Default,
			nil,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		portSetManager, err := set.ManagerInit(
			portSet,
			portSource.getPortList,
			RefreshInterval,
			logger.Default,
			nil,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		ruleManager, err := rule.ManagerInit(
			ruleTarget,
			ruleInfo.createRuleData,
			RefreshInterval,
			logger.Default,
			nil,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		eg.Go(func() error {
			return ipv4SetManager.Start(gctx)
		})

		eg.Go(func() error {
			return ipv6SetManager.Start(gctx)
		})

		eg.Go(func() error {
			return portSetManager.Start(gctx)
		})

		eg.Go(func() error {
			return ruleManager.Start(gctx)
		})

		if err := eg.Wait(); err != nil {
			logger.Default.Fatal(err)
		}
	}
}

// example of how to get set data from some external source
type listSource struct {
	path string
}

func newSource(path string) listSource {
	return listSource{path}
}

func (s *listSource) getIPList() ([]set.SetData, error) {
	return getIPListFromFile(s.path)
}

func (s *listSource) getPortList() ([]set.SetData, error) {
	return getPortListFromFile(s.path)
}

func getIPListFromFile(path string) ([]set.SetData, error) {
	list, err := readFile(path)
	if err != nil {
		return []set.SetData{}, err
	}

	return set.AddressStringsToSetData(list)
}

func getPortListFromFile(path string) ([]set.SetData, error) {
	list, err := readFile(path)
	if err != nil {
		return []set.SetData{}, err
	}

	return set.PortStringsToSetData(list)
}

func readFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return []string{}, err
	}
	defer file.Close()

	list := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			return []string{}, nil
		}
		if text[0:1] != "#" {
			list = append(list, text)
		}

	}

	if err := scanner.Err(); err != nil {
		return []string{}, err
	}

	return list, nil
}

type ruleInfo struct {
	PortSet *nftables.Set
	IPv4Set *nftables.Set
	IPv6Set *nftables.Set
}

func newRuleInfo(portSet *nftables.Set, ipv4Set *nftables.Set, ipv6Set *nftables.Set) ruleInfo {
	return ruleInfo{
		PortSet: portSet,
		IPv4Set: ipv4Set,
		IPv6Set: ipv6Set,
	}
}

func (s *ruleInfo) createRuleData() ([]rule.RuleData, error) {
	ipv6Exprs, err := rule.Build(
		expr.VerdictDrop,
		rule.AddressFamily(expressions.IPv6),
		rule.TransportProtocol(expressions.TCP),
		rule.SourceAddressSet(s.IPv6Set),
		rule.DestinationPortSet(s.PortSet),
		rule.Any(expressions.Counter()),
	)
	if err != nil {
		return nil, err
	}

	ipv4Exprs, err := rule.Build(
		expr.VerdictDrop,
		rule.AddressFamily(expressions.IPv4),
		rule.TransportProtocol(expressions.TCP),
		rule.SourceAddressSet(s.IPv4Set),
		rule.DestinationPortSet(s.PortSet),
		rule.Any(expressions.Counter()),
	)
	if err != nil {
		return nil, err
	}

	// give each rule a unique id so we can track it's existence
	ipv4Rule := rule.NewRuleData([]byte{0xd, 0xe, 0xa, 0xd}, ipv4Exprs)
	ipv6Rule := rule.NewRuleData([]byte{0xc, 0xa, 0xf, 0xe}, ipv6Exprs)

	return []rule.RuleData{ipv4Rule, ipv6Rule}, nil
}
