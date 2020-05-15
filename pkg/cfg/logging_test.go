/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"fmt"
	"testing"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_logging_setLogLevel(t *testing.T) {
	_, obs := observer.New(Logging.AtomicLogLevel)
	// type args struct {
	// }
	tests := []struct {
		name string
		lvl  zapcore.Level
	}{
		{"debug", zapcore.DebugLevel},
		{"info", zapcore.InfoLevel},
		{"warn", zapcore.WarnLevel},
		{"error", zapcore.ErrorLevel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Logging.setLogLevel(tt.lvl)
			Logging.Logger.Debugf("%s %d", tt.name, tt.lvl)
			Logging.Logger.Infof("%s %d", tt.name, tt.lvl)
			Logging.Logger.Warnf("%s %d", tt.name, tt.lvl)
			Logging.Logger.Errorf("%s %d", tt.name, tt.lvl)

			for _, logEntry := range obs.All() {
				fmt.Printf("logEntry: %+v", logEntry)
				if logEntry.Level < tt.lvl {
					t.Errorf("should not have log level of %s", logEntry.Level)
				}
				t.Logf("tt.name %s", tt.name)
			}
		})
	}
}
