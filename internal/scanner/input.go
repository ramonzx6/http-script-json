package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const maxInputBytes = 4 << 20

// DecodeTargets accepts a JSON array or an object containing urls or targets.
// Input is limited to 4 MiB.
func DecodeTargets(r io.Reader) ([]string, error) {
	if r == nil {
		return nil, fmt.Errorf("nil JSON reader")
	}
	input, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read targets JSON: %w", err)
	}
	if len(input) > maxInputBytes {
		return nil, fmt.Errorf("targets JSON exceeds the input limit of %d bytes", maxInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	var payload json.RawMessage
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode targets JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode targets JSON: multiple top-level values")
		}
		return nil, fmt.Errorf("decode targets JSON: %w", err)
	}
	var targets []string
	if err := json.Unmarshal(payload, &targets); err == nil {
		return validateTargetCount(targets)
	}
	var object struct {
		URLs    []string `json:"urls"`
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(payload, &object); err != nil {
		return nil, fmt.Errorf("targets JSON must be an array of strings or an object containing urls/targets: %w", err)
	}
	if object.URLs != nil && object.Targets != nil {
		return nil, fmt.Errorf("targets JSON must contain only one of urls or targets")
	}
	if object.URLs != nil {
		return validateTargetCount(object.URLs)
	}
	if object.Targets != nil {
		return validateTargetCount(object.Targets)
	}
	return nil, fmt.Errorf("targets JSON must be an array of strings or an object containing urls/targets")
}

func validateTargetCount(targets []string) ([]string, error) {
	if len(targets) > MaxTargets {
		return nil, fmt.Errorf("target count %d exceeds the limit of %d", len(targets), MaxTargets)
	}
	return targets, nil
}

func LoadTargets(path string, stdin io.Reader) ([]string, error) {
	if path == "-" {
		if stdin == nil {
			return nil, fmt.Errorf("nil stdin reader")
		}
		return DecodeTargets(stdin)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open targets file %q: %w", path, err)
	}
	defer file.Close()
	return DecodeTargets(file)
}
