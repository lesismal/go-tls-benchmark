package protocol

import (
	"bytes"
	"testing"
)

func TestBatchBuffers(t *testing.T) {
	msg := bytes.Repeat([]byte{'x'}, 1024)
	for _, c := range []struct {
		rate, maxLen    int
		batch, tickRate int
	}{
		// 16 fit in 16KB, but 16 does not divide 200: 10 does.
		{200, 16 << 10, 10, 20},
		{40, 16 << 10, 10, 4},
		// Never more than the rate, and never fewer than one.
		{4, 16 << 10, 4, 1},
		{7, 100, 1, 7},
	} {
		buf, batch, tickRate := BatchBuffers(msg, c.rate, c.maxLen)
		if batch != c.batch || tickRate != c.tickRate || len(buf) != batch*len(msg) {
			t.Errorf("BatchBuffers(rate %d, maxLen %d) = %d bytes, batch %d, %d/s; want batch %d, %d/s",
				c.rate, c.maxLen, len(buf), batch, tickRate, c.batch, c.tickRate)
		}
	}
}

func TestPipelineBuffers(t *testing.T) {
	buf, batch, tickRate := PipelineBuffers([]byte("ab"), 200, 8)
	if string(buf) != "abababababababab" || batch != 8 || tickRate != 25 {
		t.Errorf("PipelineBuffers = %q, %d, %d", buf, batch, tickRate)
	}
	if ValidatePipeline(0, 200) != nil || ValidatePipeline(8, 200) != nil {
		t.Error("ValidatePipeline refused a depth that divides the rate")
	}
	if ValidatePipeline(3, 200) == nil || ValidatePipeline(-1, 200) == nil {
		t.Error("ValidatePipeline accepted a depth that does not divide the rate")
	}
}

// An echo can come back cut anywhere, a record boundary or a read buffer's
// end, and has to match from wherever the last piece left off.
func TestMatchesRepeated(t *testing.T) {
	msg := []byte("0123456789")
	stream := bytes.Repeat(msg, 5)
	for _, cut := range []int{1, 3, 7, 10, 16, 50} {
		offset := 0
		for rest := stream; len(rest) > 0; {
			n := min(cut, len(rest))
			if !MatchesRepeated(rest[:n], msg, offset) {
				t.Fatalf("cut every %d: piece at %d does not match", cut, offset)
			}
			offset += n
			rest = rest[n:]
		}
	}
	if MatchesRepeated([]byte("0123x"), msg, 0) {
		t.Error("a corrupted piece matched")
	}
	if MatchesRepeated([]byte("89012"), msg, 7) {
		t.Error("a piece matched from the wrong offset")
	}
	if !MatchesRepeated([]byte("89012"), msg, 18) {
		t.Error("an offset past one copy did not wrap")
	}
}
