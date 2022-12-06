//go:build linux

package set

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"

	"github.com/ngrok/firewall_toolkit/pkg/logger"
)

type SetUpdateFunc func() ([]SetData, error)

// Represents a set managed by the manager goroutine
type ManagedSet struct {
	WaitGroup     *sync.WaitGroup
	Conn          *nftables.Conn
	Set           Set
	setUpdateFunc SetUpdateFunc
	interval      time.Duration
	logger        logger.Logger
}

// Create a set manager
func ManagerInit(wg *sync.WaitGroup, c *nftables.Conn, set Set, f SetUpdateFunc, interval time.Duration, logger logger.Logger) (ManagedSet, error) {
	return ManagedSet{
		WaitGroup:     wg,
		Conn:          c,
		Set:           set,
		setUpdateFunc: f,
		interval:      interval,
		logger:        logger,
	}, nil
}

// Start the set manager goroutine
func (s *ManagedSet) Start() {
	s.logger.Infof("starting set manager for table/set %v/%v", s.Set.Set.Table.Name, s.Set.Set.Name)
	defer s.WaitGroup.Done()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(s.interval)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				return
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
	}()

	<-sigChan
	s.logger.Infof("got sigterm, stopping set update loop for table/set %v/%v", s.Set.Set.Table.Name, s.Set.Set.Name)
}
