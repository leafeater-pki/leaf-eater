.PHONY: build test clean vet fixtures

BINARY := leafeater

build:
	go build -o $(BINARY) ./cmd/leafeater

test:
	go test ./...

vet:
	go vet ./...

fixtures:
	go run ./cmd/genfixture

clean:
	rm -f $(BINARY)
	go clean ./...
