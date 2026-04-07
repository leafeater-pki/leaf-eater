// leafeater lints Merkle Tree Certificates against draft-ietf-plants-merkle-tree-certs-02.
//
// Usage:
//
//	leafeater [flags] <path>
//
// Flags:
//
//	-format string    Output format: text, json (default "text")
//	-severity string  Minimum severity: notice, warn, error, fatal (default "notice")
//	-rules string     Comma-separated rule IDs or prefixes (default: all)
//	-strict           Treat non-MTC certs as Error rather than NA
//	-quiet            Suppress NA/Pass findings
//	-version          Print version + targeted draft revision
//
// Exit codes:
//
//	0  clean
//	1  warnings (Notice or Warn findings)
//	2  errors or fatals
//	3  usage error or unparseable input
//
// Phase 1A: single positional path, text reporter only, R001 wired.
// Directory walk, stdin, PEM chains, JSON, and -severity/-rules filtering
// beyond quiet land in Phase 1B.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/leafeater-pki/leaf-eater/internal/mtc"
	"github.com/leafeater-pki/leaf-eater/internal/reporter"
	"github.com/leafeater-pki/leaf-eater/internal/rules"

	// Register built-in rules via init().
	_ "github.com/leafeater-pki/leaf-eater/internal/rules/core"
)

// version is the leaf-eater version string plus the targeted draft revision.
const version = "leaf-eater v0.0.1-d02 (targets draft-ietf-plants-merkle-tree-certs-02, 2026-03-02)"

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

func run(stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("leafeater", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json")
	severityStr := fs.String("severity", "notice", "minimum severity: notice, warn, error, fatal")
	rulesFilter := fs.String("rules", "", "comma-separated rule IDs or prefixes (default: all)")
	strict := fs.Bool("strict", false, "treat non-MTC certs as Error rather than NA")
	quiet := fs.Bool("quiet", false, "suppress NA/Pass findings")
	showVersion := fs.Bool("version", false, "print version and targeted draft revision")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 3
	}

	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	// Phase 1A scaffolds for future use.
	_ = format
	_ = severityStr
	_ = rulesFilter
	_ = strict

	paths := fs.Args()
	if len(paths) != 1 {
		fmt.Fprintln(stderr, "leafeater: exactly one path argument required (Phase 1A)")
		fs.Usage()
		return 3
	}
	path := paths[0]

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "leafeater: %v\n", err)
		return 3
	}
	cert, err := mtc.ParseCertificate(data)
	if err != nil {
		fmt.Fprintf(stderr, "leafeater: %s: %v\n", path, err)
		return 3
	}

	findings := rules.DefaultRegistry.Run(cert)
	if err := reporter.Render(findings, stdout, path, rules.NA, *quiet); err != nil {
		fmt.Fprintf(stderr, "leafeater: reporter: %v\n", err)
		return 3
	}

	return exitCode(findings)
}

// exitCode returns the highest-severity-driven exit code per the package
// doc comment above.
func exitCode(findings []rules.Finding) int {
	maxSev := rules.NA
	for _, f := range findings {
		if f.Severity > maxSev {
			maxSev = f.Severity
		}
	}
	switch {
	case maxSev >= rules.Error:
		return 2
	case maxSev >= rules.Notice:
		return 1
	default:
		return 0
	}
}
