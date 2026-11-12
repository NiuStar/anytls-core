package main

import (
	"bytes"
	"io"
	"testing"
)

// Frozen pre-repair per-byte formula: independent of the bulk-copy algorithm.
func originalConfigEscapesRead(remaining, offset *int64, p []byte) (int, error) {
	if *remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > *remaining {
		n = int(*remaining)
	}
	const escape = `\u0020`
	for i := 0; i < n; i++ {
		p[i] = escape[(*offset+int64(i))%6]
	}
	*remaining -= int64(n)
	*offset += int64(n)
	return n, nil
}

func TestConfigEscapesReaderOracle(t *testing.T) {
	for phase := int64(0); phase < 6; phase++ {
		for _, remaining := range []int64{0, 1, 5, 6, 7, 31, 65539} {
			r := &configEscapesReader{remaining: remaining, offset: phase}
			wantRemaining, wantOffset := remaining, phase
			for _, size := range []int{0, 1, 2, 5, 6, 7, 0, 31, 65536, 8, 0} {
				got, want := bytes.Repeat([]byte{0xa5}, size+11), bytes.Repeat([]byte{0xa5}, size+11)
				n, err := r.Read(got[:size])
				wn, we := originalConfigEscapesRead(&wantRemaining, &wantOffset, want[:size])
				if n != wn || err != we || r.remaining != wantRemaining || r.offset != wantOffset || !bytes.Equal(got, want) {
					t.Fatalf("phase=%d remaining=%d size=%d n=%d want=%d err=%v want=%v state=(%d,%d) want=(%d,%d)", phase, remaining, size, n, wn, err, we, r.remaining, r.offset, wantRemaining, wantOffset)
				}
			}
		}
	}
}
