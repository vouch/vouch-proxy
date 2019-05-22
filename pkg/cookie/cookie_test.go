package cookie

import (
	"reflect"
	"testing"
)

func TestSplitCookie(t *testing.T) {
	type args struct {
		longString string
		maxLen     int
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"small split", args{"AAAbbbCCCdddEEEfffGGGhhhIIIjjj", 3}, []string{"AAA", "bbb", "CCC", "ddd", "EEE", "fff", "GGG", "hhh", "III", "jjj"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SplitCookie(tt.args.longString, tt.args.maxLen); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}
