package scanner

import (
	"bytes"
	"testing"
)

func TestDecodeTargetsRejectsInputOverLimitAfterCompleteValue(t *testing.T) {
	input := append([]byte("[]"), bytes.Repeat([]byte(" "), maxInputBytes-1)...)

	if len(input) != maxInputBytes+1 {
		t.Fatalf("test input length = %d, want %d", len(input), maxInputBytes+1)
	}
	if _, err := DecodeTargets(bytes.NewReader(input)); err == nil {
		t.Fatal("DecodeTargets accepted input over the size limit")
	}
}

func TestDecodeTargetsAcceptsInputAtLimit(t *testing.T) {
	input := append([]byte("[]"), bytes.Repeat([]byte(" "), maxInputBytes-2)...)

	if len(input) != maxInputBytes {
		t.Fatalf("test input length = %d, want %d", len(input), maxInputBytes)
	}
	targets, err := DecodeTargets(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("DecodeTargets() error = %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("DecodeTargets() = %#v, want empty targets", targets)
	}
}
