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
	Conn            *nftables.Conn
	RuleTarget      RuleTarget
	rulesUpdateFunc RulesUpdateFunc
	interval        time.Duration
	logger          logger.Logger
}

// Create a rule manager
func ManagerInit(c *nftables.Conn, ruleTarget RuleTarget, f RulesUpdateFunc, interval time.Duration, logger logger.Logger) (ManagedRules, error) {
	return ManagedRules{
		Conn:            c,
		RuleTarget:      ruleTarget,
		rulesUpdateFunc: f,
		interval:        interval,
		logger:          logger,
	}, nil
}

// Start the rule manager goroutine
func (r *ManagedRules) Start(ctx context.Context) error {
	r.logger.Infof("starting rule manager for table/chain %v/%v", r.RuleTarget.Table.Name, r.RuleTarget.Chain.Name)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(r.interval)

	for {
		select {
		case <-ctx.Done():
			r.logger.Infof("got context done, stopping rule update loop for table/chain %v/%v", r.RuleTarget.Table.Name, r.RuleTarget.Chain.Name)
			return nil
		case sig := <-sigChan:
			r.logger.Infof("got %s, stopping rule update loop for table/chain %v/%v", sig, r.RuleTarget.Table.Name, r.RuleTarget.Chain.Name)
			return nil
		case <-ticker.C:
			ruleData, err := r.rulesUpdateFunc()
			if err != nil {
				r.logger.Errorf("error with rules update function for table/chain %v/%v: %v", r.RuleTarget.Table.Name, r.RuleTarget.Chain.Name, err)
			}

			flush, err := r.RuleTarget.Update(r.Conn, ruleData)
			if err != nil {
				r.logger.Errorf("error updating rules: %v", err)
			}

			// only flush if things went well above
			if flush {
				r.logger.Infof("flushing rules for table/chain %v/%v", r.RuleTarget.Table.Name, r.RuleTarget.Chain.Name)
				if err := r.Conn.Flush(); err != nil {
					r.logger.Errorf("error flushing rules for table/chain %v/%v: %v", r.RuleTarget.Table.Name, r.RuleTarget.Chain.Name, err)
				}
			}
		}
	}
}
