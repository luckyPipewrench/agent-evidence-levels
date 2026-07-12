# SPDX-License-Identifier: Apache-2.0

# AEL reference checker + fixture corpus.
# Stdlib-only Go. Cache dirs kept under $HOME (some hosts have a quota-full /tmp).

export GOFLAGS ?= -mod=mod
BIN := ./bin

.PHONY: build gen test check fmt clean

build:
	@mkdir -p $(BIN)
	go build -o $(BIN)/aelcheck ./checker/cmd/aelcheck
	go build -o $(BIN)/aelgen   ./checker/cmd/aelgen

gen: build
	$(BIN)/aelgen --out ./fixtures

test:
	go test ./...

# The proof: regenerate the corpus, grade every case, assert it matches expect.json.
check: gen
	go test ./checker/conformance/... -run TestCorpus -v
	@echo
	@echo "=== human-readable corpus grading ==="
	go run ./checker/cmd/aelgen --report --out ./fixtures

fmt:
	gofumpt -w . 2>/dev/null || gofmt -w .

clean:
	rm -rf $(BIN)
