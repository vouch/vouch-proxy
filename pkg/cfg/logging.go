/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"os"
	"strconv"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type logging struct {
	Logger          *zap.SugaredLogger
	FastLogger      *zap.Logger
	AtomicLogLevel  zap.AtomicLevel
	DefaultLogLevel zapcore.Level
}

var (
	logger *zap.Logger
	log    *zap.SugaredLogger

	// Logging is the public interface to logging
	Logging = &logging{
		AtomicLogLevel:  zap.NewAtomicLevel(),
		DefaultLogLevel: zap.InfoLevel,
	}
)

const cmdLineLoggingDefault = -2

func init() {
	Logging.AtomicLogLevel = zap.NewAtomicLevel()
	// zap needs to start at zapcore.DebugLevel so that it can then be decreased to a lesser level
	Logging.AtomicLogLevel.SetLevel(zapcore.DebugLevel)
	encoderCfg := zap.NewProductionEncoderConfig()
	logger = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		Logging.AtomicLogLevel,
	))

	defer logger.Sync() // flushes buffer, if any
	log = logger.Sugar()
	Logging.FastLogger = logger
	Logging.Logger = log
	// 	Logging.FastLogger = zap.L()
	// 	Logging.Logger = zap.S()
	// 	log = Logging.Logger
	// log.Info("logger set")

}

func (logging) setLogLevel(lvl zapcore.Level) {
	// https://github.com/uber-go/zap/blob/master/zapcore/level.go#L59
	if Logging.AtomicLogLevel.Level() != lvl {
		log.Infof("setting LogLevel to %s", lvl)
		Logging.AtomicLogLevel.SetLevel(lvl)
	}
}

func (logging) setLogLevelString(str string) {
	if err := CmdLine.logLevel.Set(str); err != nil {
		log.Fatal(err)
	}
	Logging.setLogLevel(*CmdLine.logLevel)
}

func (logging) setDevelopmentLogger() {
	// then configure the logger for development output
	clone := Logging.FastLogger.WithOptions(
		zap.WrapCore(
			// func(zapcore.Core) zapcore.Core {
			func(zapcore.Core) zapcore.Core {
				return zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), zapcore.AddSync(os.Stderr), Logging.AtomicLogLevel)
			}))
	// zap.ReplaceGlobals(clone)
	log = clone.Sugar()
	// Logging.FastLogger = log.Desugar()
	// Logging.Logger = log
	Logging.FastLogger = log.Desugar()
	Logging.Logger = log
	log.Infof("testing: %s, using development console logger", strconv.FormatBool(Cfg.Testing))
}

var configured = false

func (logging) configure() {
	// logging

	if configured {
		return
	}

	// then we weren't configured via command line, check the config file
	if !viper.IsSet(Branding.LCName + ".logLevel") {
		// then we weren't configured via the config file, set the default
		Cfg.LogLevel = Logging.DefaultLogLevel.String()
	}

	if Cfg.LogLevel != Logging.AtomicLogLevel.Level().String() {
		// log.Errorf("Logging.configure() Logging.LogLevel %s Cfg.LogLevel %s", Logging.LogLeveLogging.String(), Cfg.LogLevel)
		Logging.setLogLevelString(Cfg.LogLevel)
	}

	// if we're supposed to run tests, run tests and exit
	if *CmdLine.logTest {
		Logging.cmdlineTestLogs()
	}

	configured = true
}

func (logging) configureFromCmdline() {

	if *CmdLine.logLevel != cmdLineLoggingDefault {
		Logging.setLogLevel(*CmdLine.logLevel) // defaults to Logging.DefaultLogLevel which is zap.InfoLevel
		log.Info("logging configured from cmdline")
		// if we're supposed to run tests, run tests and exit
		if *CmdLine.logTest {
			Logging.cmdlineTestLogs()
		}

		configured = true
	}
}

// in support of `./do.sh test_logging`
func (logging) cmdlineTestLogs() {
	Logging.Logger.Error("error")
	Logging.Logger.Warn("warn")
	Logging.Logger.Info("info")
	Logging.Logger.Debug("debug")
	// Logging.Logger.Panic("panic")
	os.Exit(0)
}
