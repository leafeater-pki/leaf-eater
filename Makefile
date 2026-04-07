.PHONY: build test clean vet

BINARY := leafeater

build:
	go build -o $(BINARY) ./cmd/leafeater

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	go clean ./...
