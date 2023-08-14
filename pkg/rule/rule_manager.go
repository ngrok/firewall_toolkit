//go:build linux

package rule

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/google/nftables"

	"github.com/ngrok/firewall_toolkit/pkg/logger"
	m "github.com/ngrok/firewall_toolkit/pkg/metrics"
)

type RulesUpdateFunc func() ([]RuleData, error)

// Represents a table/chain ruleset managed by the manager goroutine
type ManagedRules struct {
	conn            *nftables.Conn
	ruleTarget      RuleTarget
	rulesUpdateFunc RulesUpdateFunc
	interval        time.Duration
	logger          logger.Logger
	metrics         m.Metrics
}

func ManagerInit(ruleTarget RuleTarget, f RulesUpdateFunc, interval time.Duration, logger logger.Logger, metrics m.Metrics) (ManagedRules, error) {
	c, err := nftables.New()
	if err != nil {
		return ManagedRules{}, err
	}

	if metrics == nil {
		metrics = &statsd.NoOpClient{}
	}

	return ManagedRules{
		conn:            c,
		ruleTarget:      ruleTarget,
		rulesUpdateFunc: f,
		interval:        interval,
		logger:          logger,
		metrics:         metrics,
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

				err = r.metrics.Count(m.Prefix("manager_loop_update_func"), 1, r.genTags([]string{"success:false"}), 1)
				if err != nil {
					r.logger.Warnf("error sending manager_loop_update_func metric: %v", err)
				}

				continue
			}

			err = r.metrics.Count(m.Prefix("manager_loop_update_func"), 1, r.genTags([]string{"success:true"}), 1)
			if err != nil {
				r.logger.Warnf("error sending manager_loop_update_func metric: %v", err)
			}

			flush, added, deleted, err := r.ruleTarget.Update(r.conn, ruleData)
			if err != nil {
				r.logger.Errorf("error updating rules: %v", err)

				err = r.metrics.Count(m.Prefix("manager_loop_update_data"), 1, r.genTags([]string{"success:false"}), 1)
				if err != nil {
					r.logger.Warnf("error sending manager_loop_update_data metric: %v", err)
				}
			}
			err = r.metrics.Count(m.Prefix("manager_loop_update_data"), 1, r.genTags([]string{"success:true"}), 1)
			if err != nil {
				r.logger.Warnf("error sending manager_loop_update_data metric: %v", err)
			}

			rules, err := r.ruleTarget.Get(r.conn)
			if err != nil {
				r.logger.Warnf("error getting rules for sending usage count metric: %v", err)
			} else {
				for _, rule := range rules {
					r.emitUsageCounters(rule)
				}
			}

			// only flush if things went well above
			if !flush {
				continue
			}

			r.logger.Infof("flushing rules for table/chain %v/%v", r.ruleTarget.table.Name, r.ruleTarget.chain.Name)
			if err := r.conn.Flush(); err != nil {
				r.logger.Errorf("error flushing rules for table/chain %v/%v: %v", r.ruleTarget.table.Name, r.ruleTarget.chain.Name, err)
				err = r.metrics.Count(m.Prefix("manager_loop_flush"), 1, r.genTags([]string{"success:false"}), 1)
				if err != nil {
					r.logger.Warnf("error sending manager_loop_flush metric: %v", err)
				}
				continue
			}
			err = r.metrics.Count(m.Prefix("manager_loop_update_data_added"), int64(added), r.genTags([]string{}), 1)
			if err != nil {
				r.logger.Warnf("error sending manager_loop_update_data_added metric: %v", err)
			}
			err = r.metrics.Count(m.Prefix("manager_loop_update_data_deleted"), int64(deleted), r.genTags([]string{}), 1)
			if err != nil {
				r.logger.Warnf("error sending manager_loop_update_data_deleted metric: %v", err)
			}
			err = r.metrics.Count(m.Prefix("manager_loop_flush"), 1, r.genTags([]string{"success:true"}), 1)
			if err != nil {
				r.logger.Warnf("error sending manager_loop_flush metric: %v", err)
			}
		}
	}
}

// Get the rule target that this manager is operating on
func (r *ManagedRules) GetRuleTarget() RuleTarget {
	return r.ruleTarget
}

func (r *ManagedRules) genTags(additional []string) []string {
	defaultTags := []string{
		"manager_type:rule",
		fmt.Sprintf("table:%s", r.ruleTarget.table.Name),
		fmt.Sprintf("chain:%s", r.ruleTarget.chain.Name),
	}

	return append(additional, defaultTags...)
}

func (r *ManagedRules) emitUsageCounters(ruleData RuleData) {
	bytes, packets, err := ruleData.getCounters()
	if err != nil {
		r.logger.Warnf("error getting rule counter: %v", err)
		return
	}
	err = r.metrics.Count(m.Prefix("fwng-agent.bytes"), *bytes, r.genTags([]string{fmt.Sprintf("id:%s", ruleData.ID)}), 1)
	if err != nil {
		r.logger.Warnf("error sending fng-agent.bytes metric: %v", err)
	}
	err = r.metrics.Count(m.Prefix("fwng-agent.packets"), *packets, r.genTags([]string{fmt.Sprintf("id:%s", ruleData.ID)}), 1)
	if err != nil {
		r.logger.Warnf("error sending fng-agent.packets metric: %v", err)
	}
}
