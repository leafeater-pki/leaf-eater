// leafeater lints Merkle Tree Certificates against draft-ietf-plants-merkle-tree-certs-02.
//
// Usage:
//
//	leafeater [flags] <path...>
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
//	1  warnings
//	2  errors or fatals
//	3  usage error
//
// Phase 0: the CLI parses flags and prints version info but does not yet
// execute any rules. Rule execution returns "no rules registered" and exit 0.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is the leaf-eater version string plus the targeted draft revision.
const version = "leaf-eater v0.0.1-d02 (targets draft-ietf-plants-merkle-tree-certs-02, 2026-03-02)"

func main() {
	os.Exit(run())
}

func run() int {
	format := flag.String("format", "text", "output format: text, json")
	severityStr := flag.String("severity", "notice", "minimum severity: notice, warn, error, fatal")
	rulesFilter := flag.String("rules", "", "comma-separated rule IDs or prefixes (default: all)")
	strict := flag.Bool("strict", false, "treat non-MTC certs as Error rather than NA")
	quiet := flag.Bool("quiet", false, "suppress NA/Pass findings")
	showVersion := flag.Bool("version", false, "print version and targeted draft revision")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	// Silence "declared and not used" for Phase 0 stubs; Phase 1 wires these up.
	_ = format
	_ = severityStr
	_ = rulesFilter
	_ = strict
	_ = quiet

	paths := flag.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "leafeater: no paths specified")
		flag.Usage()
		return 3
	}

	// Phase 0: rule execution is a stub. No rules are registered.
	fmt.Fprintln(os.Stderr, "leafeater: no rules registered (Phase 0 scaffold)")
	return 0
}
