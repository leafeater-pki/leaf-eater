// Package loader normalizes certificate input from files, directories, or
// stdin into a uniform stream of Items. PEM chains are split into one Item
// per block; DER inputs pass through unchanged. Each Item carries a
// provenance tag of the form "<source>#<index>".
package loader

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Item is a single cert's worth of bytes plus its provenance tag.
// If Err is non-nil, this Item represents an error rather than cert data.
type Item struct {
	Source string
	Data   []byte
	Err    error
}

// Loader produces a stream of Items when Load is called. The returned
// channel is closed once the loader has emitted all items or the context
// is cancelled.
type Loader interface {
	Load(ctx context.Context) <-chan Item
}

// certExts is the set of file extensions treated as candidate certificate
// files during directory walks. Matching is case-insensitive.
var certExts = map[string]bool{
	".pem": true,
	".der": true,
	".crt": true,
	".cer": true,
}

// isPEM reports whether data looks like PEM (starts with '-').
func isPEM(data []byte) bool {
	return len(data) > 0 && data[0] == '-'
}

// sendItem sends item on out, respecting ctx cancellation. Returns false
// if the context was cancelled before the send completed.
func sendItem(ctx context.Context, out chan<- Item, item Item) bool {
	select {
	case out <- item:
		return true
	case <-ctx.Done():
		return false
	}
}

// emitBlocks splits data into one or more Items and sends them on out.
// DER inputs produce a single Item with suffix "#0". PEM inputs are split
// block-by-block; each block is re-encoded as a self-contained PEM blob so
// downstream consumers that detect PEM via a leading '-' still work.
func emitBlocks(ctx context.Context, out chan<- Item, source string, data []byte) {
	if !isPEM(data) {
		sendItem(ctx, out, Item{Source: source + "#0", Data: data})
		return
	}

	rest := data
	idx := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return
		}
		var buf bytes.Buffer
		if err := pem.Encode(&buf, block); err != nil {
			if !sendItem(ctx, out, Item{Source: fmt.Sprintf("%s#%d", source, idx), Err: err}) {
				return
			}
			idx++
			continue
		}
		if !sendItem(ctx, out, Item{Source: fmt.Sprintf("%s#%d", source, idx), Data: buf.Bytes()}) {
			return
		}
		idx++
	}
}

// fileLoader loads a single file.
type fileLoader struct {
	path string
}

// FileLoader returns a Loader that reads a single file and emits one Item
// per certificate found (one per PEM block, or one for a DER file).
func FileLoader(path string) Loader {
	return &fileLoader{path: path}
}

func (l *fileLoader) Load(ctx context.Context) <-chan Item {
	out := make(chan Item, 1)
	go func() {
		defer close(out)
		data, err := os.ReadFile(l.path)
		if err != nil {
			sendItem(ctx, out, Item{Source: l.path, Err: err})
			return
		}
		emitBlocks(ctx, out, l.path, data)
	}()
	return out
}

// dirLoader walks a directory tree.
type dirLoader struct {
	root string
}

// DirLoader returns a Loader that walks root recursively, reading each
// file whose extension matches .pem/.der/.crt/.cer (case-insensitive) and
// emitting one Item per certificate found within.
func DirLoader(root string) Loader {
	return &dirLoader{root: root}
}

func (l *dirLoader) Load(ctx context.Context) <-chan Item {
	out := make(chan Item, 8)
	go func() {
		defer close(out)
		walkErr := filepath.WalkDir(l.root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				sendItem(ctx, out, Item{Source: path, Err: err})
				return nil
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if !certExts[ext] {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				if !sendItem(ctx, out, Item{Source: path, Err: readErr}) {
					return filepath.SkipAll
				}
				return nil
			}
			emitBlocks(ctx, out, path, data)
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			return nil
		})
		if walkErr != nil && walkErr != filepath.SkipAll {
			sendItem(ctx, out, Item{Source: l.root, Err: walkErr})
		}
	}()
	return out
}

// stdinLoader reads from an io.Reader (defaulting to os.Stdin).
type stdinLoader struct {
	r io.Reader
}

// StdinLoader returns a Loader that reads os.Stdin.
func StdinLoader() Loader {
	return &stdinLoader{r: os.Stdin}
}

// StdinLoaderFrom returns a Loader that reads from r. Useful for tests
// that want to inject a reader instead of the real stdin.
func StdinLoaderFrom(r io.Reader) Loader {
	return &stdinLoader{r: r}
}

func (l *stdinLoader) Load(ctx context.Context) <-chan Item {
	out := make(chan Item, 1)
	go func() {
		defer close(out)
		data, err := io.ReadAll(l.r)
		if err != nil {
			sendItem(ctx, out, Item{Source: "<stdin>", Err: err})
			return
		}
		emitBlocks(ctx, out, "<stdin>", data)
	}()
	return out
}
