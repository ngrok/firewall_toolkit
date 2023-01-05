//go:build linux

package rule

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/nftables"

	"github.com/ngrok/firewall_toolkit/pkg/logger"
)

type RulesUpdateFunc func() ([]RuleData, error)

// Represents a table/chain ruleset managed by the manager goroutine
type ManagedRules struct {
	conn            *nftables.Conn
	ruleTarget      RuleTarget
	rulesUpdateFunc RulesUpdateFunc
	interval        time.Duration
	logger          logger.Logger
}

// Create a rule manager
func ManagerInit(ruleTarget RuleTarget, f RulesUpdateFunc, interval time.Duration, logger logger.Logger) (ManagedRules, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return ManagedRules{}, err
	}

	return ManagedRules{
		conn:            c,
		ruleTarget:      ruleTarget,
		rulesUpdateFunc: f,
		interval:        interval,
		logger:          logger,
	}, nil
}

// Start the rule manager goroutine
func (r *ManagedRules) Start(ctx context.Context) error {
	r.logger.Infof("starting rule manager for table/chain %v/%v", r.ruleTarget.table.Name, r.ruleTarget.chain.Name)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(r.interval)

	for {
		select {
		case <-ctx.Done():
			r.logger.Infof("got context done, stopping rule update loop for table/chain %v/%v", r.ruleTarget.table.Name, r.ruleTarget.chain.Name)
			return nil
		case sig := <-sigChan:
			r.logger.Infof("got %s, stopping rule update loop for table/chain %v/%v", sig, r.ruleTarget.table.Name, r.ruleTarget.chain.Name)
			return nil
		case <-ticker.C:
			ruleData, err := r.rulesUpdateFunc()
			if err != nil {
				r.logger.Errorf("error with rules update function for table/chain %v/%v: %v", r.ruleTarget.table.Name, r.ruleTarget.chain.Name, err)
			}

			flush, err := r.ruleTarget.Update(r.conn, ruleData)
			if err != nil {
				r.logger.Errorf("error updating rules: %v", err)
			}

			// only flush if things went well above
			if flush {
				r.logger.Infof("flushing rules for table/chain %v/%v", r.ruleTarget.table.Name, r.ruleTarget.chain.Name)
				if err := r.conn.Flush(); err != nil {
					r.logger.Errorf("error flushing rules for table/chain %v/%v: %v", r.ruleTarget.table.Name, r.ruleTarget.chain.Name, err)
				}
			}
		}
	}
}

// Get the rule target that this manager is operating on
func (r *ManagedRules) GetRuleTarget() RuleTarget {
	return r.ruleTarget
}
