.PHONY: all lint generate build clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

all: lint generate build

lint:
	golangci-lint run ./...

generate:
	go generate ./...

build:
	mkdir -p bin
	go build -buildvcs=false $(LDFLAGS) -o bin/bpflite ./cmd/bpflite

clean:
	rm -rf bin
	rm -f bpf/*_bpfel.go
	rm -f bpf/*_bpfel.o
