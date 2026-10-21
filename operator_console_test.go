package main

import (
	"strings"
	"testing"
)

func TestOperatorConsoleCLIRejectsInvalidArgumentsBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"version", "extra"}, "usage"},
		{[]string{"reload", "extra"}, "usage"},
		{[]string{"service-reload", "-arbitrary-command"}, "invalid service-reload"},
		{[]string{"password", "unexpected"}, "usage"},
		{[]string{"update", "--version", "https://example.invalid/payload"}, "version must be stable"},
		{[]string{"webui", "--port", "0"}, "port"},
		{[]string{"webui", "--port", "65536"}, "port"},
	} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			if err := execute(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted argument rejection containing %q; got %v", tc.want, err)
			}
		})
	}
}
