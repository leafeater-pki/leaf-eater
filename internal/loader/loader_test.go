package loader

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLoader_SingleFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cert.pem")
	content := []byte("-----BEGIN CERTIFICATE-----\nMIIBATCB\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ch := FileLoader(p).Load(ctx)
	var items []Item
	for item := range ch {
		items = append(items, item)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	if items[0].Source != p+"#0" {
		t.Errorf("source: want %q got %q", p+"#0", items[0].Source)
	}
}

func TestFileLoader_PEMChain(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "chain.pem")
	content := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" +
		"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatal(err)
	}
	ch := FileLoader(p).Load(context.Background())
	var items []Item
	for item := range ch {
		items = append(items, item)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 chain items, got %d", len(items))
	}
	if !strings.HasSuffix(items[0].Source, "#0") || !strings.HasSuffix(items[1].Source, "#1") {
		t.Errorf("chain indices wrong: %q %q", items[0].Source, items[1].Source)
	}
}

func TestFileLoader_DER(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cert.der")
	content := []byte{0x30, 0x82, 0x01, 0x00}
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatal(err)
	}
	ch := FileLoader(p).Load(context.Background())
	var items []Item
	for item := range ch {
		items = append(items, item)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 DER item, got %d", len(items))
	}
	if !bytes.Equal(items[0].Data, content) {
		t.Errorf("DER data mismatch")
	}
}

func TestDirLoader_WalksPEMAndDER(t *testing.T) {
	dir := t.TempDir()
	pemContent := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	derContent := []byte{0x30, 0x82}
	os.WriteFile(filepath.Join(dir, "a.pem"), pemContent, 0644)
	os.WriteFile(filepath.Join(dir, "b.der"), derContent, 0644)
	os.WriteFile(filepath.Join(dir, "c.txt"), []byte("ignored"), 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "d.crt"), pemContent, 0644)

	ch := DirLoader(dir).Load(context.Background())
	var sources []string
	for item := range ch {
		sources = append(sources, item.Source)
	}
	if len(sources) != 3 {
		t.Fatalf("want 3 items (a.pem, b.der, sub/d.crt), got %d: %v", len(sources), sources)
	}
}

func TestStdinLoader_PEM(t *testing.T) {
	content := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	ch := StdinLoaderFrom(strings.NewReader(content)).Load(context.Background())
	var items []Item
	for item := range ch {
		items = append(items, item)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	if !strings.HasPrefix(items[0].Source, "<stdin>") {
		t.Errorf("stdin source tag wrong: %q", items[0].Source)
	}
}
