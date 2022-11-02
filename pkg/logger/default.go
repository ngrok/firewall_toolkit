package logger

import (
	"log"
	"os"
)

var Default Logger = defaultLogger{}

type defaultLogger struct{}

func (defaultLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format+"\n", args...)
}

func (defaultLogger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format+"\n", args...)
}

func (defaultLogger) Warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+format+"\n", args...)
}

func (defaultLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format+"\n", args...)
}

func (defaultLogger) Fatalf(format string, args ...interface{}) {
	log.Printf("[FATAL] "+format+"\n", args...)
	os.Exit(1)
}

func (defaultLogger) Fatal(args ...interface{}) {
	log.Print(args...)
	os.Exit(1)
}
