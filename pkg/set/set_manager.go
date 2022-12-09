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
	Conn          *nftables.Conn
	Set           Set
	setUpdateFunc SetUpdateFunc
	interval      time.Duration
	logger        logger.Logger
}

// Create a set manager
func ManagerInit(c *nftables.Conn, set Set, f SetUpdateFunc, interval time.Duration, logger logger.Logger) (ManagedSet, error) {
	return ManagedSet{
		Conn:          c,
		Set:           set,
		setUpdateFunc: f,
		interval:      interval,
		logger:        logger,
	}, nil
}

// Start the set manager goroutine
func (s *ManagedSet) Start(ctx context.Context) error {
	s.logger.Infof("starting set manager for table/set %v/%v", s.Set.Set.Table.Name, s.Set.Set.Name)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(s.interval)

	for {
		select {
		case <-ctx.Done():
			s.logger.Infof("got context done, stopping set update loop for table/set %v/%v", s.Set.Set.Table.Name, s.Set.Set.Name)
			return nil
		case sig := <-sigChan:
			s.logger.Infof("got %s, stopping set update loop for table/set %v/%v", sig, s.Set.Set.Table.Name, s.Set.Set.Name)
			return nil
		case <-ticker.C:
			data, err := s.setUpdateFunc()
			if err != nil {
				s.logger.Errorf("error with set update function for table/set %v/%v: %v", s.Set.Set.Table.Name, s.Set.Set.Name, err)
				continue
			}

			flush, err := s.Set.UpdateElements(s.Conn, data)
			if err != nil {
				s.logger.Errorf("error updating table/set %v/%v: %v", s.Set.Set.Table.Name, s.Set.Set.Name, err)
				continue
			}

			// only flush if things went well above
			if flush {
				if err := s.Conn.Flush(); err != nil {
					s.logger.Errorf("error flushing table/set %v/%v: %v", s.Set.Set.Table.Name, s.Set.Set.Name, err)
				}
			}
		}
	}
}
