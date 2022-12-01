//go:build linux

package rule

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"

	"github.com/ngrok/firewall_toolkit/pkg/logger"
)

type RulesUpdateFunc func() ([]RuleData, error)

// Represents a table/chain ruleset managed by the manager goroutine
type ManagedRules struct {
	WaitGroup       *sync.WaitGroup
	Conn            *nftables.Conn
	Table           *nftables.Table
	Chain           *nftables.Chain
	rulesUpdateFunc RulesUpdateFunc
	interval        time.Duration
	logger          logger.Logger
}

// Create a rule manager
func ManagerInit(wg *sync.WaitGroup, c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, f RulesUpdateFunc, interval time.Duration, logger logger.Logger) (ManagedRules, error) {
	return ManagedRules{
		WaitGroup:       wg,
		Conn:            c,
		Table:           table,
		Chain:           chain,
		rulesUpdateFunc: f,
		interval:        interval,
		logger:          logger,
	}, nil
}

// Start the rule manager goroutine
func (r *ManagedRules) Start() {
	r.logger.Infof("starting rule manager for table/chain %v/%v", r.Table.Name, r.Chain.Name)
	defer r.WaitGroup.Done()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(r.interval)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				flush := true
				addCount := 0

				ruleData, err := r.rulesUpdateFunc()
				if err != nil {
					r.logger.Errorf("error with rules update function for table/chain %v/%v: %v", r.Table.Name, r.Chain.Name, err)
					flush = false
				}

				for _, rD := range ruleData {
					added, err := Add(r.Conn, r.Table, r.Chain, rD)
					if err != nil {
						r.logger.Errorf("error adding rule %x for table/chain %v/%v: %v", rD.ID, r.Table.Name, r.Chain.Name, err)
						flush = false
					}

					if added {
						r.logger.Infof("added rule %x for table/chain %v/%v", rD.ID, r.Table.Name, r.Chain.Name)
						addCount++
					}
				}

				// dont flush if we didn't do anyhting
				if addCount == 0 {
					flush = false
				}

				// only flush if things went well above
				if flush {
					r.logger.Infof("flushing %v rules for table/chain %v/%v", addCount, r.Table.Name, r.Chain.Name)
					if err := r.Conn.Flush(); err != nil {
						r.logger.Errorf("error flushing rules for table/chain %v/%v: %v", r.Table.Name, r.Chain.Name, err)
					}
				}
			}
		}
	}()

	<-sigChan
	r.logger.Infof("got sigterm, stopping rule update loop for table/chain %v/%v", r.Table.Name, r.Chain.Name)
}