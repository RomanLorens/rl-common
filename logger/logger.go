package logger

import (
	"context"
	"os"

	"github.com/RomanLorens/logger/log"
)

//L app logger
var L log.Logger

func init() {
	path := os.Getenv("COMMON_LOG")
	if path == "" {
		path = "logs/common.log"
	}
	_l, err := log.New(log.WithConfig(path).Build())
	if err != nil {
		_l.Error(context.Background(), "Could not create file logger, %v", err)
	}
	L = _l
}
