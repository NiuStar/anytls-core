package startuptimeline

import (
	"errors"
	"strings"
	"testing"
)

func TestStrictRequest(t *testing.T) {
	valid := `{"timeline_schema":1,"action":"startup.read","operation_id":null}`
	var q ReadRequest
	if err := Decode(strings.NewReader(valid), &q); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`{"timeline_schema":1,"timeline_schema":1,"action":"startup.read","operation_id":null}`,
		`{"timeline_schema":1,"action":"startup.read","operation_id":null,"secret":"PRIVATE"}`,
		`{"timeline_schema":1,"action":"startup.read"}`,
		`{"timeline_schema":null,"action":"startup.read","operation_id":null}`,
		`{"timeline_schema":1,"action":"startup.read","operation_id":1}`,
		`{"timeline_schema":2,"action":"startup.read","operation_id":null}`,
		`{"timeline_schema":1,"action":"startup.push","operation_id":null}`,
		valid + valid,
		strings.Replace(valid, "startup.read", `startup.\u0000read`, 1),
		string([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
	}
	for i, raw := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			var out ReadRequest
			if err := Decode(strings.NewReader(raw), &out); err == nil {
				t.Fatal("strict invalid request accepted")
			}
		})
	}
	if err := Decode(strings.NewReader(valid+strings.Repeat(" ", LegacyBytes)), &q); !errors.Is(err, TooLarge) {
		t.Fatalf("budget code: %v", err)
	}
	b, err := Encode(ReadRequest{1, "startup.read", nil})
	if err != nil || len(b) == 0 || b[len(b)-1] != '\n' {
		t.Fatalf("newline framing: %q %v", b, err)
	}
}
