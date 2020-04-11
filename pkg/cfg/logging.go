package cfg

import (
	"fmt"
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
	LogLevel        zapcore.Level
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

func (L logging) setLogLevel(lvl zapcore.Level) {
	// https://github.com/uber-go/zap/blob/master/zapcore/level.go#L59
	L.LogLevel = lvl
	log.Debugf("setting LogLevel to %s", lvl)
	L.AtomicLogLevel.SetLevel(lvl)
	log.Debugf("set LogLevel to %s", lvl)
}

func (L logging) setLogLevelString(str string) {
	if err := CmdLine.logLevel.Set(str); err != nil {
		log.Fatal(err)
	}
	L.setLogLevel(*CmdLine.logLevel)
}

func (L logging) setDevelopmentLogger() {
	// then configure the logger for development output
	clone := L.FastLogger.WithOptions(
		zap.WrapCore(
			// func(zapcore.Core) zapcore.Core {
			func(zapcore.Core) zapcore.Core {
				return zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), zapcore.AddSync(os.Stderr), Logging.AtomicLogLevel)
			}))
	// zap.ReplaceGlobals(clone)
	log = clone.Sugar()
	L.FastLogger = log.Desugar()
	L.Logger = log
	log.Infof("testing: %s, using development console logger", strconv.FormatBool(Cfg.Testing))
}

func (L logging) configure() {
	// logging
	if *CmdLine.logLevel != -1 {
		if !viper.IsSet(Branding.LCName + ".logLevel") {
			Cfg.LogLevel = fmt.Sprintf("%s", Logging.DefaultLogLevel)
		}

		if Cfg.LogLevel != Logging.LogLevel.String() {
			Logging.setLogLevelString(Cfg.LogLevel)
		}
	}
}
