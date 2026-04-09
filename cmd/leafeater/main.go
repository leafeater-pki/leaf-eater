// leafeater lints Merkle Tree Certificates against draft-ietf-plants-merkle-tree-certs-02.
//
// Usage:
//
//	leafeater [flags] <path>
//	leafeater [flags] <dir>
//	leafeater [flags] -       (read from stdin)
//	cat cert.pem | leafeater  (read from stdin)
//
// Flags:
//
//	-format string    Output format: text, json (default "text")
//	-severity string  Minimum severity: na, ne, pass, notice, warn, error, fatal (default "notice")
//	-rules string     Comma-separated rule IDs to run (default: all)
//	-strict           Treat non-MTC certs as Error for R001 (default: NA)
//	-quiet            Suppress NA/Pass findings
//	-version          Print version and targeted draft revision
//
// Exit codes:
//
//	0  clean (no findings at Notice or above)
//	1  warnings (highest finding was Notice or Warn)
//	2  errors or fatals
//	3  usage error, IO error, or unparseable input
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/leafeater-pki/leaf-eater/internal/loader"
	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/reporter"
	"github.com/leafeater-pki/leaf-eater/internal/rules"

	// Named import: init() registers the built-in rules, and main calls
	// core.SetStrictR001 to plumb the -strict flag through to R001.
	core "github.com/leafeater-pki/leaf-eater/internal/rules/core"
)

// version is the leaf-eater version string plus the targeted draft revision.
const version = "leaf-eater v0.1.0-d02 (targets draft-ietf-plants-merkle-tree-certs-02, 2026-03-02)"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run parses args and drives the linter. Factored out of main() so tests can
// exercise it without touching os.Args/os.Exit.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("leafeater", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json")
	severityStr := fs.String("severity", "notice", "minimum severity: na, ne, pass, notice, warn, error, fatal")
	rulesArg := fs.String("rules", "", "comma-separated rule IDs to run (default: all)")
	strict := fs.Bool("strict", false, "treat non-MTC certs as Error for R001")
	quiet := fs.Bool("quiet", false, "suppress NA/Pass findings")
	showVersion := fs.Bool("version", false, "print version and targeted draft revision")
	if err := fs.Parse(args); err != nil {
		return 3
	}

	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	core.SetStrictR001(*strict)

	minSev, err := parseSeverity(*severityStr)
	if err != nil {
		fmt.Fprintln(stderr, "leafeater:", err)
		return 3
	}

	ruleAllow := parseRuleList(*rulesArg)

	paths := fs.Args()
	var ld loader.Loader
	switch {
	case len(paths) == 0 || (len(paths) == 1 && paths[0] == "-"):
		ld = loader.StdinLoaderFrom(stdin)
	case len(paths) == 1:
		info, statErr := os.Stat(paths[0])
		if statErr != nil {
			fmt.Fprintln(stderr, "leafeater:", statErr)
			return 3
		}
		if info.IsDir() {
			ld = loader.DirLoader(paths[0])
		} else {
			ld = loader.FileLoader(paths[0])
		}
	default:
		fmt.Fprintf(stderr, "leafeater: only one path argument supported (got %d)\n", len(paths))
		return 3
	}

	return runLinter(ld, *format, minSev, *quiet, ruleAllow, stdout, stderr)
}

// runLinter consumes items from ld, runs the rule registry against each,
// filters by ruleAllow, and dispatches to the requested reporter. Returns
// the exit code.
func runLinter(ld loader.Loader, format string, minSev rules.Severity, quiet bool, ruleAllow map[string]bool, stdout, stderr io.Writer) int {
	ctx := context.Background()
	worstSev := rules.NA
	var jsonStream *reporter.JSONStreamer
	if format == "json" {
		jsonStream = reporter.NewJSONStreamer(stdout, minSev, quiet)
		defer jsonStream.Close()
	}

	hadIOError := false
	for item := range ld.Load(ctx) {
		if item.Err != nil {
			fmt.Fprintln(stderr, "leafeater: io error:", item.Source, item.Err)
			hadIOError = true
			continue
		}
		cert, parseErr := mtc.ParseCertificate(item.Data)
		if parseErr != nil {
			fmt.Fprintln(stderr, "leafeater: parse error:", item.Source, parseErr)
			hadIOError = true
			continue
		}
		findings := rules.DefaultRegistry.Run(cert)
		findings = filterByRules(findings, ruleAllow)
		for _, f := range findings {
			if f.Severity > worstSev {
				worstSev = f.Severity
			}
		}
		switch format {
		case "json":
			if err := jsonStream.Write(findings, item.Source); err != nil {
				fmt.Fprintln(stderr, "leafeater: reporter error:", err)
				return 3
			}
		default: // text
			if err := reporter.Render(findings, stdout, item.Source, minSev, quiet); err != nil {
				fmt.Fprintln(stderr, "leafeater: reporter error:", err)
				return 3
			}
		}
	}

	if hadIOError {
		return 3
	}
	switch {
	case worstSev >= rules.Error:
		return 2
	case worstSev >= rules.Notice:
		return 1
	default:
		return 0
	}
}

// parseSeverity maps a user-supplied severity string to the rules.Severity
// enum. Accepts both the canonical names and a few aliases (warn/warning,
// error/err).
func parseSeverity(s string) (rules.Severity, error) {
	switch strings.ToLower(s) {
	case "na":
		return rules.NA, nil
	case "ne":
		return rules.NE, nil
	case "pass":
		return rules.Pass, nil
	case "notice":
		return rules.Notice, nil
	case "warn", "warning":
		return rules.Warn, nil
	case "error", "err":
		return rules.Error, nil
	case "fatal":
		return rules.Fatal, nil
	default:
		return 0, fmt.Errorf("unknown severity %q (valid: na, ne, pass, notice, warn, error, fatal)", s)
	}
}

// parseRuleList parses a comma-separated list of rule IDs into an allowlist
// map. Returns nil on empty input, meaning "allow all rules".
func parseRuleList(s string) map[string]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, id := range strings.Split(s, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			m[id] = true
		}
	}
	return m
}

// filterByRules drops findings whose rule ID isn't in the allowlist. Returns
// the original slice unchanged when allow is nil (meaning all rules).
func filterByRules(findings []rules.Finding, allow map[string]bool) []rules.Finding {
	if allow == nil {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if allow[f.RuleID] {
			out = append(out, f)
		}
	}
	return out
}
