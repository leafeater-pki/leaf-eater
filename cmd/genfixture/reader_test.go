package main

import (
	"bytes"
	"testing"
)

func TestDetReader_Deterministic(t *testing.T) {
	r1 := &detReader{seed: []byte("leafeater-fixture-seed-v1")}
	r2 := &detReader{seed: []byte("leafeater-fixture-seed-v1")}
	b1 := make([]byte, 1024)
	b2 := make([]byte, 1024)
	if _, err := r1.Read(b1); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Read(b2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("detReader produced different output for identical seeds")
	}
}

func TestDetReader_ReturnsFullLength(t *testing.T) {
	r := &detReader{seed: []byte("x")}
	buf := make([]byte, 100)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 100 {
		t.Errorf("n = %d, want 100", n)
	}
}
