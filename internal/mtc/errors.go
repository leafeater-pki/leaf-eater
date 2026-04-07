// Package mtc defines the wire-format types and parser for Merkle Tree
// Certificates per draft-ietf-plants-merkle-tree-certs-02.
package mtc

import "fmt"

// ParseError is the typed error returned by the MTC parser. It carries
// a field path (e.g. "MTCProof.inclusion_proof[3]"), a byte offset within
// the input, and a wrapped cause.
//
// Strict mode: malformed input always yields a ParseError. No partial results,
// no recovery.
type ParseError struct {
	// Field is the dotted field path where the error occurred
	// (e.g. "Certificate.signatureValue.MTCProof.start").
	Field string
	// Offset is the byte offset within the input where the error occurred.
	// Zero if not applicable.
	Offset int
	// Cause is the wrapped underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("mtc parse error at %s (offset %d): %v", e.Field, e.Offset, e.Cause)
	}
	return fmt.Sprintf("mtc parse error at %s (offset %d)", e.Field, e.Offset)
}

// Unwrap returns the wrapped cause, enabling errors.Is / errors.As.
func (e *ParseError) Unwrap() error {
	return e.Cause
}
