//go:build linux

package set

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/nftables"

	"github.com/ngrok/firewall_toolkit/pkg/logger"
)

type SetUpdateFunc func() ([]SetData, error)

// Represents a set managed by the manager goroutine
type ManagedSet struct {
	conn          *nftables.Conn
	set           Set
	setUpdateFunc SetUpdateFunc
	interval      time.Duration
	logger        logger.Logger
}

// Create a set manager
func ManagerInit(set Set, f SetUpdateFunc, interval time.Duration, logger logger.Logger) (ManagedSet, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return ManagedSet{}, err
	}

	return ManagedSet{
		conn:          c,
		set:           set,
		setUpdateFunc: f,
		interval:      interval,
		logger:        logger,
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
			data, err := s.setUpdateFunc()
			if err != nil {
				s.logger.Errorf("error with set update function for table/set %v/%v: %v", s.set.set.Table.Name, s.set.set.Name, err)
				continue
			}

			flush, err := s.set.UpdateElements(s.conn, data)
			if err != nil {
				s.logger.Errorf("error updating table/set %v/%v: %v", s.set.set.Table.Name, s.set.set.Name, err)
				continue
			}

			// only flush if things went well above
			if flush {
				if err := s.conn.Flush(); err != nil {
					s.logger.Errorf("error flushing table/set %v/%v: %v", s.set.set.Table.Name, s.set.set.Name, err)
				}
			}
		}
	}
}

// Get the set this manager is operating on
func (s *ManagedSet) GetSet() Set {
	return s.set
}
