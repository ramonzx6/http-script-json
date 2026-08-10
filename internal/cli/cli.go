package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ramonzx6/http-script-json/internal/scanner"
)

const version = "0.1.0"

// Main runs the command and returns a process exit code. Keeping I/O
// injectable makes the command straightforward to test without network calls.
func Main(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	flags := flag.NewFlagSet("rapid-reset-check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr, flags) }
	var inputPath string
	var outputFormat string
	var jsonOutput bool
	var timeout time.Duration
	var concurrency int
	var maxAddresses int
	var allowPrivate bool
	var caFile string
	var showVersion bool
	flags.StringVar(&inputPath, "input", "", "JSON file containing an array of targets (or - for stdin)")
	flags.StringVar(&outputFormat, "format", "text", "output format: text or json")
	flags.BoolVar(&jsonOutput, "json", false, "shortcut for --format json")
	flags.DurationVar(&timeout, "timeout", scanner.DefaultOptions.Timeout, "DNS and per-address timeout")
	flags.IntVar(&concurrency, "concurrency", scanner.DefaultOptions.Concurrency, "maximum concurrent targets (limit 128)")
	flags.IntVar(&maxAddresses, "max-addresses", scanner.DefaultOptions.MaxAddresses, "maximum resolved addresses tested per target (limit 64)")
	flags.BoolVar(&allowPrivate, "allow-private", false, "allow loopback/private/reserved addresses; use only for controlled targets")
	flags.StringVar(&caFile, "ca-file", "", "PEM CA bundle to trust in addition to normal system roots")
	flags.BoolVar(&showVersion, "version", false, "print version")
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			printUsage(stdout, flags)
			return 0
		}
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		fmt.Fprintf(stdout, "rapid-reset-check %s\n", version)
		return 0
	}
	if jsonOutput {
		outputFormat = "json"
	}
	outputFormat = strings.ToLower(strings.TrimSpace(outputFormat))
	if outputFormat != "text" && outputFormat != "json" {
		fmt.Fprintf(stderr, "invalid --format %q; choose text or json\n", outputFormat)
		return 2
	}
	if timeout <= 0 || concurrency <= 0 || maxAddresses <= 0 {
		fmt.Fprintln(stderr, "timeout, concurrency, and max-addresses must be positive")
		return 2
	}

	targets := append([]string(nil), flags.Args()...)
	if inputPath != "" && len(targets) > 0 {
		fmt.Fprintln(stderr, "--input and positional targets are mutually exclusive")
		return 2
	}
	if inputPath != "" {
		fromJSON, err := scanner.LoadTargets(inputPath, stdin)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		targets = fromJSON
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "at least one positional target or --input JSON file is required")
		printUsage(stderr, flags)
		return 2
	}
	if len(targets) > scanner.MaxTargets {
		fmt.Fprintf(stderr, "target count %d exceeds the limit of %d\n", len(targets), scanner.MaxTargets)
		return 2
	}

	options := scanner.Options{
		Concurrency:  concurrency,
		Timeout:      timeout,
		MaxAddresses: maxAddresses,
		AllowPrivate: allowPrivate,
		CAFile:       caFile,
	}
	probe, err := scanner.New(options)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	results := probe.Scan(context.Background(), targets)
	if outputFormat == "json" {
		if err := writeJSON(stdout, scanner.NewReport(results)); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	} else {
		writeText(stdout, results)
	}
	for _, result := range results {
		if !result.Complete {
			return 1
		}
	}
	return 0
}

func printUsage(out io.Writer, flags *flag.FlagSet) {
	fmt.Fprintln(out, "rapid-reset-check performs an active-but-minimal TLS ALPN check for HTTP/2 exposure.")
	fmt.Fprintln(out, "It sends no HTTP request, HTTP/2 preface, stream, reset, or flood traffic.")
	fmt.Fprintln(out, "HTTP/2 exposure does not prove CVE-2023-44487 vulnerability or patch status.")
	fmt.Fprintln(out, "\nUsage: rapid-reset-check [flags] target [target ...]")
	fmt.Fprintln(out, "       rapid-reset-check --input urls.json [flags]")
	fmt.Fprintln(out, "\nFlags:")
	previousOutput := flags.Output()
	flags.SetOutput(out)
	flags.PrintDefaults()
	flags.SetOutput(previousOutput)
}

func writeJSON(out io.Writer, report scanner.Report) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func writeText(out io.Writer, results []scanner.Result) {
	fmt.Fprintln(out, "rapid-reset-check: active-but-minimal TLS ALPN scan")
	for _, result := range results {
		protocol := result.Protocol
		if protocol == "" {
			protocol = "-"
		}
		fmt.Fprintf(out, "%s\t%s\tcomplete=%t\tprotocol=%s\taddresses=%d/%d\tomitted=%d\tduration=%dms\n", result.Target, result.Classification, result.Complete, protocol, len(result.Addresses), result.ResolvedAddressCount, result.OmittedAddressCount, result.DurationMillis)
		fmt.Fprintf(out, "  %s\n", result.ClassificationReason)
		for _, address := range result.Addresses {
			switch {
			case address.PolicyBlocked:
				fmt.Fprintf(out, "  address=%s policy=blocked\n", address.Address)
			case address.Error != "":
				fmt.Fprintf(out, "  address=%s error=%s\n", address.Address, address.Error)
			default:
				fmt.Fprintf(out, "  address=%s alpn=%s tls=%s\n", address.Address, address.TLS.NegotiatedProtocol, address.TLS.Version)
			}
		}
		if result.Error != "" {
			fmt.Fprintf(out, "  error=%s\n", result.Error)
		}
	}
	summary := scanner.Summarize(results)
	fmt.Fprintf(out, "summary: total=%d complete=%d incomplete=%d h2_observed=%d h2_not_observed=%d indeterminate=%d policy=%d invalid=%d\n", summary.Total, summary.Complete, summary.Incomplete, summary.H2ObservedReview, summary.H2NotObserved, summary.Indeterminate, summary.NotScannedPolicy, summary.InvalidTarget)
}

// Run is convenient for the conventional os.Args-based main function.
func Run() int { return Main(os.Args[1:], os.Stdout, os.Stderr, os.Stdin) }
