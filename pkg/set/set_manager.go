//go:build linux

package set

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
	"github.com/ngrok/firewall_toolkit/pkg/utils"
)

type SetUpdateFunc func() ([]SetData, error)

// Represents a set managed by the manager goroutine
type ManagedSet struct {
	conn          *nftables.Conn
	set           Set
	setUpdateFunc SetUpdateFunc
	interval      time.Duration
	logger        logger.Logger
	metrics       m.Metrics
}

// Create a set manager.
// Passing a nil metrics object is safe and will result in the "NoOp" client being used.
func ManagerInit(set Set, f SetUpdateFunc, interval time.Duration, logger logger.Logger, metrics m.Metrics) (ManagedSet, error) {
	c, err := nftables.New()
	if err != nil {
		return ManagedSet{}, err
	}

	if metrics == nil {
		metrics = &statsd.NoOpClient{}
	}

	return ManagedSet{
		conn:          c,
		set:           set,
		setUpdateFunc: f,
		interval:      interval,
		logger:        logger,
		metrics:       metrics,
	}, nil
}

// Start the set manager goroutine
func (s *ManagedSet) Start(ctx context.Context) error {
	s.logger.Infof("starting set manager for table/set %v/%v", s.set.set.Table.Name, s.set.set.Name)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(s.interval)

	for {
		select {
		case <-ctx.Done():
			s.logger.Infof("got context done, stopping set update loop for table/set %v/%v", s.set.set.Table.Name, s.set.set.Name)
			return nil
		case sig := <-sigChan:
			s.logger.Infof("got %s, stopping set update loop for table/set %v/%v", sig, s.set.set.Table.Name, s.set.set.Name)
			return nil
		case <-ticker.C:
			countedSetData, err := s.set.getCountedSetData(s.conn)
			if err != nil {
				s.logger.Warnf("error getting set data for sending usage count metric: %v", err)
			} else {
				s.emitUsageCounters(countedSetData)
			}

			data, err := s.setUpdateFunc()
			if err != nil {
				s.logger.Errorf("error with set update function for table/set %v/%v: %v", s.set.set.Table.Name, s.set.set.Name, err)
				err = s.metrics.Count(m.Prefix("manager_loop_update_func"), 1, s.genTags([]string{"success:false"}), 1)
				if err != nil {
					s.logger.Warnf("error sending manager_loop_update_func metric: %v", err)
				}
				continue
			}
			err = s.metrics.Count(m.Prefix("manager_loop_update_func"), 1, s.genTags([]string{"success:true"}), 1)
			if err != nil {
				s.logger.Warnf("error sending manager_loop_update_func metric: %v", err)
			}

			flush, added, deleted, err := s.set.UpdateElements(s.conn, data)
			if err != nil {
				s.logger.Errorf("error updating table/set %v/%v: %v", s.set.set.Table.Name, s.set.set.Name, err)
				err = s.metrics.Count(m.Prefix("manager_loop_update_data"), 1, s.genTags([]string{"success:false"}), 1)
				if err != nil {
					s.logger.Warnf("error sending manager_loop_update_data metric: %v", err)
				}
				continue
			}
			err = s.metrics.Count(m.Prefix("manager_loop_update_data"), 1, s.genTags([]string{"success:true"}), 1)
			if err != nil {
				s.logger.Warnf("error sending manager_loop_update_data metric: %v", err)
			}

			// only flush if things went well above
			if !flush {
				continue
			}

			if err := s.conn.Flush(); err != nil {
				s.logger.Errorf("error flushing table/set %v/%v: %v", s.set.set.Table.Name, s.set.set.Name, err)
				err = s.metrics.Count(m.Prefix("manager_loop_flush"), 1, s.genTags([]string{"success:false"}), 1)
				if err != nil {
					s.logger.Warnf("error sending manager_loop_flush metric: %v", err)
				}
				continue
			}
			err = s.metrics.Count(m.Prefix("manager_loop_update_data_added"), int64(added), s.genTags([]string{}), 1)
			if err != nil {
				s.logger.Warnf("error sending manager_loop_update_data_added metric: %v", err)
			}
			err = s.metrics.Count(m.Prefix("manager_loop_update_data_deleted"), int64(deleted), s.genTags([]string{}), 1)
			if err != nil {
				s.logger.Warnf("error sending manager_loop_update_data_deleted metric: %v", err)
			}
			err = s.metrics.Count(m.Prefix("manager_loop_flush"), 1, s.genTags([]string{"success:true"}), 1)
			if err != nil {
				s.logger.Warnf("error sending manager_loop_flush metric: %v", err)
			}
		}
	}
}

// Get the set this manager is operating on
func (s *ManagedSet) GetSet() Set {
	return s.set
}

func (s *ManagedSet) genTags(additional []string) []string {
	defaultTags := []string{
		"manager_type:set",
		fmt.Sprintf("table:%s", s.set.set.Table.Name),
		fmt.Sprintf("set:%s", s.set.set.Name),
	}

	return append(additional, defaultTags...)
}

func (s *ManagedSet) emitUsageCounters(setDataList []countedSetData) {
	for _, setData := range setDataList {
		var tags []string
		if err := utils.ValidatePort(setData.setData.Port); err != nil {
			tags = []string{fmt.Sprintf("range-start:%v", setData.setData.Port)}
		} else if err := utils.ValidatePortRange(setData.setData.PortRangeStart, setData.setData.PortRangeEnd); err != nil {
			tags = []string{fmt.Sprintf("range-start:%v", setData.setData.PortRangeStart), fmt.Sprintf("range-end:%v", setData.setData.PortRangeEnd)}
		} else if err := utils.ValidatePrefix(setData.setData.Prefix); err != nil {
			tags = []string{fmt.Sprintf("range-start:%s", setData.setData.Prefix)}
		} else if err := utils.ValidateAddress(setData.setData.Address); err != nil {
			tags = []string{fmt.Sprintf("range-start:%s", setData.setData.Address)}
		} else if err := utils.ValidateAddressRange(setData.setData.AddressRangeStart, setData.setData.AddressRangeEnd); err != nil {
			tags = []string{fmt.Sprintf("range-start:%s", setData.setData.AddressRangeStart), fmt.Sprintf("range-end:%s", setData.setData.AddressRangeEnd)}
		} else {
			s.logger.Warnf("invalid set data encountered while emitting counter metrics: %+v", setData.setData)
			continue
		}

		err := s.metrics.Count(m.Prefix("fwng-agent.bytes"), setData.bytes, s.genTags(tags), 1)
		if err != nil {
			s.logger.Warnf("error sending fwng-agent.bytes metric: %v", err)
		}
		err = s.metrics.Count(m.Prefix("fwng-agent.packets"), setData.packets, s.genTags(tags), 1)
		if err != nil {
			s.logger.Warnf("error sending fwng-agent.packets metric: %v", err)
		}
	}
}
