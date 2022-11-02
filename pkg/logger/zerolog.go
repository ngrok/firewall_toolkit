package logger

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

var Zerolog Logger = zerologLogger{}

type zerologLogger struct{}

func (zerologLogger) Debugf(format string, args ...interface{}) {
	log.Debug().Msg(fmt.Sprintf(format, args...))
}

func (zerologLogger) Infof(format string, args ...interface{}) {
	log.Info().Msg(fmt.Sprintf(format, args...))
}

func (zerologLogger) Warnf(format string, args ...interface{}) {
	log.Warn().Msg(fmt.Sprintf(format, args...))
}

func (zerologLogger) Errorf(format string, args ...interface{}) {
	log.Error().Msg(fmt.Sprintf(format, args...))
}

func (zerologLogger) Fatalf(format string, args ...interface{}) {
	log.Fatal().Msg(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func (zerologLogger) Fatal(args ...interface{}) {
	log.Fatal().Msg(fmt.Sprint(args...))
	os.Exit(1)
}
