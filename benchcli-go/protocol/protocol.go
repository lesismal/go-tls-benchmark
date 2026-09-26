// Package protocol is what the benchmark client writes on a TLS connection:
// the message, the message again, and nothing else. The servers echo the
// plaintext stream back as it is, so there is no framing to encode or parse;
// what is left is how BenchPipeline batches messages into writes, and how it
// checks an echo that arrives in pieces.
package protocol

import (
	"bytes"
	"fmt"
)

// BatchBuffers is buf repeated as many times as fit in maxLen, and no fewer
// than once - fewer if that many would not divide rate - with that count and
// how many times a second the batch has to be written to send rate copies of
// buf a second.
func BatchBuffers(buf []byte, rate, maxLen int) ([]byte, int, int) {
	batch := maxLen / len(buf)
	if batch < 1 {
		batch = 1
	}
	if batch > rate {
		batch = rate
	}
	for (batch > 1) && (rate%batch != 0) {
		batch--
	}
	return bytes.Repeat(buf, batch), batch, rate / batch
}

// PipelineBuffers is buf repeated pipeline times, with how many times a second
// that batch has to be written to send rate copies of buf a second. pipeline
// has to divide rate; see ValidatePipeline.
func PipelineBuffers(buf []byte, rate, pipeline int) ([]byte, int, int) {
	return bytes.Repeat(buf, pipeline), pipeline, rate / pipeline
}

// ValidatePipeline checks a requested pipeline depth against the send rate:
// 0 asks for the depth BatchBuffers works out, and anything else has to divide
// rate, since the batch is written a whole number of times a second.
func ValidatePipeline(pipeline, rate int) error {
	switch {
	case pipeline < 0:
		return fmt.Errorf("pipeline %d: want 0, which fits as many messages as -rbs holds, or more", pipeline)
	case pipeline > 0 && rate%pipeline != 0:
		return fmt.Errorf("pipeline %d does not divide the send rate %d, so no whole number of"+
			" writes a second sends it; pick a divisor of %d", pipeline, rate, rate)
	}
	return nil
}

// MatchesRepeated reports whether data is what a stream of msg repeated end
// to end holds from offset bytes into one of its copies on.
func MatchesRepeated(data, msg []byte, offset int) bool {
	offset %= len(msg)
	for len(data) > 0 {
		n := min(len(data), len(msg)-offset)
		if !bytes.Equal(data[:n], msg[offset:offset+n]) {
			return false
		}
		data = data[n:]
		offset = 0
	}
	return true
}
